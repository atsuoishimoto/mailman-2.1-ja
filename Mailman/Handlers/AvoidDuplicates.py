# Copyright (C) 2002-2003 by the Free Software Foundation, Inc.
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
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

"""If the user wishes it, do not send duplicates of the same message.

This module keeps an in-memory dictionary of Message-ID: and recipient pairs.
If a message with an identical Message-ID: is about to be sent to someone who
has already received a copy, we either drop the message, add a duplicate
warning header, or pass it through, depending on the user's preferences.
"""

from email.Utils import getaddresses, formataddr
from Mailman import mm_cfg

COMMASPACE = ', '

try:
    True, False
except NameError:
    True = 1
    False = 0



def process(mlist, msg, msgdata):
    recips = msgdata['recips']
    # Short circuit
    if not recips:
        return
    # Seed this set with addresses we don't care about dup avoiding
    explicit_recips = {}
    listaddrs = [mlist.GetListEmail(), mlist.GetBouncesEmail(),
                 mlist.GetOwnerEmail(), mlist.GetRequestEmail()]
    for addr in listaddrs:
        explicit_recips[addr] = True
    # Figure out the set of explicit recipients
    ccaddrs = {}
    for header in ('to', 'cc', 'resent-to', 'resent-cc'):
        addrs = getaddresses(msg.get_all(header, []))
        if header == 'cc':
            for name, addr in addrs:
                ccaddrs[addr] = name, addr
        for name, addr in addrs:
            if not addr:
                continue
            # Ignore the list addresses for purposes of dup avoidance
            explicit_recips[addr] = True
    # Now strip out the list addresses
    for addr in listaddrs:
        del explicit_recips[addr]
    if not explicit_recips:
        # No one was explicitly addressed, so we can't do any dup collapsing
        return
    newrecips = []
    for r in recips:
        # If this recipient is explicitly addressed...
        if explicit_recips.has_key(r):
            send_duplicate = True
            # If the member wants to receive duplicates, or if the recipient
            # is not a member at all, just flag the X-Mailman-Duplicate: yes
            # header.
            if mlist.isMember(r) and \
                   mlist.getMemberOption(r, mm_cfg.DontReceiveDuplicates):
                send_duplicate = False
            # We'll send a duplicate unless the user doesn't wish it.  If
            # personalization is enabled, the add-dupe-header flag will add a
            # X-Mailman-Duplicate: yes header for this user's message.
            if send_duplicate:
                msgdata.setdefault('add-dup-header', {})[r] = True
                newrecips.append(r)
            elif ccaddrs.has_key(r):
                del ccaddrs[r]
        else:
            # Otherwise, this is the first time they've been in the recips
            # list.  Add them to the newrecips list and flag them as having
            # received this message.
            newrecips.append(r)
    # Set the new list of recipients
    msgdata['recips'] = newrecips
    # RFC 2822 specifies zero or one CC header
    del msg['cc']
    if ccaddrs:
        msg['Cc'] = COMMASPACE.join([formataddr(i) for i in ccaddrs.values()])
