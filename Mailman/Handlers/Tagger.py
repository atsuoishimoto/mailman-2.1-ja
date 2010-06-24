# Copyright (C) 2001-2008 by the Free Software Foundation, Inc.
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

"""Extract topics from the original mail message.
"""

import re
import email
import email.Errors

from email.header import Header, make_header, decode_header
from Mailman.Utils import GetCharSet

OR = '|'
COMMA = ','



def process(mlist, msg, msgdata):
    if not mlist.topics_enabled:
        return
    # Set language charset
    lcset = GetCharSet(mlist.preferred_language)
    # Extract the Subject:, Keywords:, and possibly body text
    matchlines = []
    matchlines.append(u_oneline(msg.get('subject', u'')))
    matchlines.append(u_oneline(msg.get('keywords', u'')))
    if mlist.topics_bodylines_limit == 0:
        # Don't scan any body lines
        pass
    elif mlist.topics_bodylines_limit < 0:
        # Scan all body lines
        matchlines.extend(scanbody(msg, lcset))
    else:
        # Scan just some of the body lines
        matchlines.extend(scanbody(msg, lcset, mlist.topics_bodylines_limit))
    matchlines = filter(None, matchlines)
    # For each regular expression in the topics list, see if any of the lines
    # of interest from the message match the regexp.  If so, the message gets
    # added to the specific topics bucket.
    hits = {}
    for name, pattern, desc, emptyflag in mlist.topics:
        pattern = OR.join(pattern.splitlines())
        pattern = unicode(pattern, lcset)
        cre = re.compile(pattern, re.IGNORECASE | re.VERBOSE)
        for line in matchlines:
            if cre.search(line):
                hits[name] = 1
                break
    if hits:
        msgdata['topichits'] = hits.keys()
        x_topics = COMMA.join(hits.keys())
        try:
            unicode(x_topics, 'us-ascii')
        except:
            x_topics = unicode(x_topics, lcset, 'replace')
            x_topics = Header(x_topics.encode('utf-8'), 'utf-8')
        msg['X-Topics'] = str(x_topics)



def scanbody(msg, lcset, numlines=None):
    # We only scan the body of the message if it is of MIME type text/plain,
    # or if the outer type is multipart/alternative and there is a text/plain
    # part.  Anything else, and the body is ignored for header-scan purposes.
    found = None
    if msg.get_content_type() == 'text/plain':
        found = msg
    else:
        for found in msg.walk():
            if found.get_content_type() == 'text/plain':
                break
        else:
            found = None
    if not found:
        return []
    # Now that we have a Message object that meets our criteria, let's extract
    # the first numlines of body text.
    mcset = found.get_content_charset(lcset)
    lines = []
    lineno = 0
    reader = found.get_payload(decode=True).splitlines()
    while numlines is None or lineno < numlines:
        try:
            line = reader.pop(0)
        except IndexError:
            break
        # Blank lines don't count
        if not line.strip():
            continue
        lineno += 1
        lines.append(unicode(line, mcset))
    return lines


def u_oneline(s):
    # Decode header string in one line
    try:
        h = make_header(decode_header(s))
        ustr = unicode(h)
        return u''.join(ustr.splitlines())
    except:
        return u'' # return empty string
