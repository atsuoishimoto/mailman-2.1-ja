# Copyright (C) 2001-2010 by the Free Software Foundation, Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, 
# MA 02110-1301, USA.

"""Cleanse a message for archiving."""

from __future__ import nested_scopes

import os
import re
import time
import errno

from email.Utils import parsedate
from mimetypes import guess_all_extensions

from Mailman import mm_cfg
from Mailman import Utils
from Mailman import LockFile
from Mailman import Message
from Mailman.Errors import DiscardMessage
from Mailman.i18n import _
from Mailman.Logging.Syslog import syslog
from Mailman.Utils import sha_new

# Path characters for common platforms
pre = re.compile(r'[/\\:]')
# All other characters to strip out of Content-Disposition: filenames
# (essentially anything that isn't an alphanum, dot, dash, or underscore).
sre = re.compile(r'[^-\w.]')
# Regexp to strip out leading dots
dre = re.compile(r'^\.*')

BR = '<br>\n'
SPACE = ' '


def guess_extension(ctype, ext):
    # mimetypes maps multiple extensions to the same type, e.g. .doc, .dot,
    # and .wiz are all mapped to application/msword.  This sucks for finding
    # the best reverse mapping.  If the extension is one of the giving
    # mappings, we'll trust that, otherwise we'll just guess. :/
    all = guess_all_extensions(ctype, strict=False)
    if ext in all:
        return ext
    return all and all[0]


def safe_strftime(fmt, t):
    try:
        return time.strftime(fmt, t)
    except (TypeError, ValueError, OverflowError):
        return None


def calculate_attachments_dir(mlist, msg, msgdata):
    # Calculate the directory that attachments for this message will go
    # under.  To avoid inode limitations, the scheme will be:
    # archives/private/<listname>/attachments/YYYYMMDD/<msgid-hash>/<files>
    # Start by calculating the date-based and msgid-hash components.
    fmt = '%Y%m%d'
    datestr = msg.get('Date')
    if datestr:
        now = parsedate(datestr)
    else:
        now = time.gmtime(msgdata.get('received_time', time.time()))
    datedir = safe_strftime(fmt, now)
    if not datedir:
        datestr = msgdata.get('X-List-Received-Date')
        if datestr:
            datedir = safe_strftime(fmt, datestr)
    if not datedir:
        # What next?  Unixfrom, I guess.
        parts = msg.get_unixfrom().split()
        try:
            month = {'Jan':1, 'Feb':2, 'Mar':3, 'Apr':4, 'May':5, 'Jun':6,
                     'Jul':7, 'Aug':8, 'Sep':9, 'Oct':10, 'Nov':11, 'Dec':12,
                     }.get(parts[3], 0)
            day = int(parts[4])
            year = int(parts[6])
        except (IndexError, ValueError):
            # Best we can do I think
            month = day = year = 0
        datedir = '%04d%02d%02d' % (year, month, day)
    assert datedir
    # As for the msgid hash, we'll base this part on the Message-ID: so that
    # all attachments for the same message end up in the same directory (we'll
    # uniquify the filenames in that directory as needed).  We use the first 2
    # and last 2 bytes of the SHA1 hash of the message id as the basis of the
    # directory name.  Clashes here don't really matter too much, and that
    # still gives us a 32-bit space to work with.
    msgid = msg['message-id']
    if msgid is None:
        msgid = msg['Message-ID'] = Utils.unique_message_id(mlist)
    # We assume that the message id actually /is/ unique!
    digest = sha_new(msgid).hexdigest()
    return os.path.join('attachments', datedir, digest[:4] + digest[-4:])


def replace_payload_by_text(msg, text, charset):
    # TK: This is a common function in replacing the attachment and the main
    # message by a text (scrubbing).
    del msg['content-type']
    del msg['content-transfer-encoding']
    if isinstance(charset, unicode):
        # email 3.0.1 (python 2.4) doesn't like unicode
        charset = charset.encode('us-ascii')
    msg.set_payload(text, charset)


class Scrubber:
    """ TK: Scrubber class is introduced for convenience.
        It has common initializer and functions to save the attachment
        and compose short text to describe it.
    """
    def __init__(self, mlist, msg, msgdata, msgtexts):
        self.mlist = mlist
        self.msg = msg
        self.msgdata = msgdata
        self.msgtexts = msgtexts
        self.dir = calculate_attachments_dir(self.mlist, self.msg,
                                              self.msgdata)
        self.lcset = Utils.GetCharSet(self.mlist.preferred_language)

    def scrub_text(self, part):
        # Plain text scrubber.
        omask = os.umask(002)
        try:
            url = save_attachment(self.mlist, part, self.dir)
        finally:
            os.umask(omask)
        filename = part.get_filename(_('not available'))
        filename = Utils.oneline(filename, self.lcset)
        self.msgtexts.append(unicode(_("""\
An embedded and charset-unspecified text was scrubbed...
Name: %(filename)s
URL: %(url)s
"""), self.lcset))

    def scrub_html3(self, part):
        # sanitize == 3
        omask = os.umask(002)
        try:
            url = save_attachment(self.mlist, part, self.dir,
                                  filter_html=False)
        finally:
            os.umask(omask)
        self.msgtexts.append(unicode(_("""\
An HTML attachment was scrubbed...
URL: %(url)s
"""), self.lcset))

    def scrub_html1(self, part):
        # sanitize == 1
        payload = Utils.websafe(part.get_payload(decode=True))
        # For whitespace in the margin, change spaces into
        # non-breaking spaces, and tabs into 8 of those.  Then use a
        # mono-space font.  Still looks hideous to me, but then I'd
        # just as soon discard them.
        def doreplace(s):
            return s.expandtabs(8).replace(' ', '&nbsp;')
        lines = [doreplace(s) for s in payload.split('\n')]
        payload = '<tt>\n' + BR.join(lines) + '\n</tt>\n'
        part.set_payload(payload)
        # We're replacing the payload with the decoded payload so this
        # will just get in the way.
        del part['content-transfer-encoding']
        omask = os.umask(002)
        try:
            url = save_attachment(self.mlist, part, self.dir,
                                  filter_html=False)
        finally:
            os.umask(omask)
        self.msgtexts.append(unicode(_("""\
An HTML attachment was scrubbed...
URL: %(url)s
"""), self.lcset))

    def scrub_msg822(self, part):
        # submessage
        submsg = part.get_payload(0)
        omask = os.umask(002)
        try:
            url = save_attachment(self.mlist, part, self.dir)
        finally:
            os.umask(omask)
        subject = submsg.get('subject', _('no subject'))
        subject = Utils.oneline(subject, self.lcset)
        date = submsg.get('date', _('no date'))
        who = submsg.get('from', _('unknown sender'))
        size = len(str(submsg))
        self.msgtexts.append(unicode(_("""\
An embedded message was scrubbed...
From: %(who)s
Subject: %(subject)s
Date: %(date)s
Size: %(size)s
URL: %(url)s
"""), self.lcset))
        # Replace this part because subparts should not be walk()-ed.
        del part['content-type']
        part.set_payload('blah blah', 'us-ascii')

    def scrub_any(self, part):
        # Images and MS Office files and all
        payload = part.get_payload(decode=True)
        ctype = part.get_content_type()
        # XXX email 2.5 special care is omitted.
        size = len(payload)
        omask = os.umask(002)
        try:
            url = save_attachment(self.mlist, part, self.dir)
        finally:
            os.umask(omask)
        desc = part.get('content-description', _('not available'))
        desc = Utils.oneline(desc, self.lcset)
        filename = part.get_filename(_('not available'))
        filename = Utils.oneline(filename, self.lcset)
        self.msgtexts.append(unicode(_("""\
A non-text attachment was scrubbed...
Name: %(filename)s
Type: %(ctype)s
Size: %(size)d bytes
Desc: %(desc)s
URL: %(url)s
"""), self.lcset))



def process(mlist, msg, msgdata=None):
    sanitize = mm_cfg.ARCHIVE_HTML_SANITIZER
    outer = True
    if msgdata is None:
        msgdata = {}
    if msgdata:
        # msgdata is available if it is in GLOBAL_PIPELINE
        # ie. not in digest or archiver
        # check if the list owner want to scrub regular delivery
        if not mlist.scrub_nondigest:
            return
    # You don't have to scrub if the msg is plain text
    if msg.get_content_type == 'plain/text':
        return msg    # should return msg if called from archiver etc.
    dir = calculate_attachments_dir(mlist, msg, msgdata)
    charset = None
    lcset = Utils.GetCharSet(mlist.preferred_language)
    mcset = format_param = delsp_param = None
    fbcset = 'utf-8' # fall back charset
    # compose replaced texts in unicode string fragments
    msgtexts = []
    firsttext = True
    scrubber = Scrubber(mlist, msg, msgdata, msgtexts)
    # Now walk over all subparts of this message and scrub out various types
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        ctype = part.get_content_type()
        # Get the first text/plain part and set message charset etc
        # Note that lcset is reserved for fall back if the content cannot
        # be encoded by the original message charset.
        if not mcset and ctype == 'text/plain':
            mcset = part.get_content_charset('us-ascii')
            format_param = part.get_param('format')
            delsp_param = part.get_param('delsp')
        # For all text/plain, we check if it is attachment.
        if ctype == 'text/plain':
            # check message charset (eg. 'unknown' should be None)
            cset = part.get_content_charset()
            try:
                u''.encode(cset)
            except (LookupError, TypeError):
                if firsttext:
                    cset = 'us-ascii'
                else:
                    cset = None
            # check Content-Disposition Header
            cd = part.get('content-disposition', '').lower()
            if 'attachment' in cd or not cset:
                scrubber.scrub_text(part)
            else:
                text = part.get_payload(decode=True)
                msgtexts.append(unicode(text, cset, 'replace'))
                firsttext = False
        elif ctype == 'text/html' and isinstance(sanitize, int):
            if sanitize == 0:
                if outer:
                    raise DiscardMessage
                msgtexts.append(unicode(
                                 _('HTML attachment scrubbed and removed'),
                                 # Adding charset arg and removing content-type
                                 # sets content-type to text/plain
                                 lcset))
            elif sanitize == 2:
                # By leaving it alone, Pipermail will automatically escape it
                pass
            elif sanitize == 3:
                # Pull it out as an attachment but leave it unescaped.  This
                # is dangerous, but perhaps useful for heavily moderated
                # lists.
                scrubber.scrub_html3(part)
            else:
                # HTML-escape it and store it as an attachment, but make it
                # look a /little/ bit prettier. :(
                scrubber.scrub_html1(part)
        elif ctype == 'message/rfc822':
            # This part contains a submessage, so it too needs scrubbing
            scrubber.scrub_msg822(part)
        # If the message isn't a multipart, then we'll strip it out as an
        # attachment that would have to be separately downloaded.  Pipermail
        # will transform the url into a hyperlink.
        elif part.get_payload() and not part.is_multipart():
            scrubber.scrub_any(part)
        outer = False
    # Now join the msgtexts and set the payload
    sep = unicode(_('-------------- next part --------------\n'), lcset)
    sep = u'\n' + sep # Let's make it simple. Always add \n.
    msgtext = sep.join(msgtexts)
    del msg['content-type']
    del msg['content-transfer-encoding']
    # Now try encoding message by mcset, lcset, fbcset order.
    try:
        msg.set_payload(msgtext.encode(mcset), mcset)
    except (UnicodeEncodeError, TypeError):
        try:
            msg.set_payload(msgtext.encode(lcset), lcset)
        except UnicodeEncodeError:
            # fall back = utf-8 should work always
            msg.set_payload(msgtext.encode(fbcset), fbcset)
    if format_param:
        msg.set_param('Format', format_param)
    if delsp_param:
        msg.set_param('DelSp', delsp_param)
    # Content-Transfer-Encoding depends on the charset chosen.
    return msg



def makedirs(dir):
    # Create all the directories to store this attachment in
    try:
        os.makedirs(dir, 02775)
        # Unfortunately, FreeBSD seems to be broken in that it doesn't honor
        # the mode arg of mkdir().
        def twiddle(arg, dirname, names):
            os.chmod(dirname, 02775)
        os.path.walk(dir, twiddle, None)
    except OSError, e:
        if e.errno <> errno.EEXIST: raise



def save_attachment(mlist, msg, dir, filter_html=True):
    fsdir = os.path.join(mlist.archive_dir(), dir)
    makedirs(fsdir)
    # Figure out the attachment type and get the decoded data
    decodedpayload = msg.get_payload(decode=True)
    # BAW: mimetypes ought to handle non-standard, but commonly found types,
    # e.g. image/jpg (should be image/jpeg).  For now we just store such
    # things as application/octet-streams since that seems the safest.
    ctype = msg.get_content_type()
    # i18n file name is encoded
    lcset = Utils.GetCharSet(mlist.preferred_language)
    filename = Utils.oneline(msg.get_filename(''), lcset)
    filename, fnext = os.path.splitext(filename)
    # For safety, we should confirm this is valid ext for content-type
    # but we can use fnext if we introduce fnext filtering
    if mm_cfg.SCRUBBER_USE_ATTACHMENT_FILENAME_EXTENSION:
        # HTML message doesn't have filename :-(
        ext = fnext or guess_extension(ctype, fnext)
    else:
        ext = guess_extension(ctype, fnext)
    if not ext:
        # We don't know what it is, so assume it's just a shapeless
        # application/octet-stream, unless the Content-Type: is
        # message/rfc822, in which case we know we'll coerce the type to
        # text/plain below.
        if ctype == 'message/rfc822':
            ext = '.txt'
        else:
            ext = '.bin'
    # Allow only alphanumerics, dash, underscore, and dot
    ext = sre.sub('', ext)
    path = None
    # We need a lock to calculate the next attachment number
    lockfile = os.path.join(fsdir, 'attachments.lock')
    lock = LockFile.LockFile(lockfile)
    lock.lock()
    try:
        # Now base the filename on what's in the attachment, uniquifying it if
        # necessary.
        if not filename or mm_cfg.SCRUBBER_DONT_USE_ATTACHMENT_FILENAME:
            filebase = 'attachment'
        else:
            # Sanitize the filename given in the message headers
            parts = pre.split(filename)
            filename = parts[-1]
            # Strip off leading dots
            filename = dre.sub('', filename)
            # Allow only alphanumerics, dash, underscore, and dot
            filename = sre.sub('', filename)
            # If the filename's extension doesn't match the type we guessed,
            # which one should we go with?  For now, let's go with the one we
            # guessed so attachments can't lie about their type.  Also, if the
            # filename /has/ no extension, then tack on the one we guessed.
            # The extension was removed from the name above.
            filebase = filename
        # Now we're looking for a unique name for this file on the file
        # system.  If msgdir/filebase.ext isn't unique, we'll add a counter
        # after filebase, e.g. msgdir/filebase-cnt.ext
        counter = 0
        extra = ''
        while True:
            path = os.path.join(fsdir, filebase + extra + ext)
            # Generally it is not a good idea to test for file existance
            # before just trying to create it, but the alternatives aren't
            # wonderful (i.e. os.open(..., O_CREAT | O_EXCL) isn't
            # NFS-safe).  Besides, we have an exclusive lock now, so we're
            # guaranteed that no other process will be racing with us.
            if os.path.exists(path):
                counter += 1
                extra = '-%04d' % counter
            else:
                break
    finally:
        lock.unlock()
    # `path' now contains the unique filename for the attachment.  There's
    # just one more step we need to do.  If the part is text/html and
    # ARCHIVE_HTML_SANITIZER is a string (which it must be or we wouldn't be
    # here), then send the attachment through the filter program for
    # sanitization
    if filter_html and ctype == 'text/html':
        base, ext = os.path.splitext(path)
        tmppath = base + '-tmp' + ext
        fp = open(tmppath, 'w')
        try:
            fp.write(decodedpayload)
            fp.close()
            cmd = mm_cfg.ARCHIVE_HTML_SANITIZER % {'filename' : tmppath}
            progfp = os.popen(cmd, 'r')
            decodedpayload = progfp.read()
            status = progfp.close()
            if status:
                syslog('error',
                       'HTML sanitizer exited with non-zero status: %s',
                       status)
        finally:
            os.unlink(tmppath)
        # BAW: Since we've now sanitized the document, it should be plain
        # text.  Blarg, we really want the sanitizer to tell us what the type
        # if the return data is. :(
        ext = '.txt'
        path = base + '.txt'
    # Is it a message/rfc822 attachment?
    elif ctype == 'message/rfc822':
        submsg = msg.get_payload()
        # BAW: I'm sure we can eventually do better than this. :(
        decodedpayload = Utils.websafe(str(submsg))
    fp = open(path, 'w')
    fp.write(decodedpayload)
    fp.close()
    # Now calculate the url
    baseurl = mlist.GetBaseArchiveURL()
    # Private archives will likely have a trailing slash.  Normalize.
    if baseurl[-1] <> '/':
        baseurl += '/'
    # A trailing space in url string may save users who are using
    # RFC-1738 compliant MUA (Not Mozilla).
    # Trailing space will definitely be a problem with format=flowed.
    # Bracket the URL instead.
    url = '<' + baseurl + '%s/%s%s%s>' % (dir, filebase, extra, ext)
    return url
