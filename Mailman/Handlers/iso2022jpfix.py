#
# fix "machine dependent characters" in iso-2022-jp
# ... if found, convert them into utf-8
# by tkikuchi 2010/06/25
# 
import pykf

def process(mlist, msg, msgdata):
    for m in msg.walk():
        if m.get_content_type() == 'text/plain' and\
           m.get_content_charset() == 'iso-2022-jp':
            break
    else:
        return
    s = m.get_payload(decode=True)
    try:
        unicode(s, 'iso-2022-jp')
        return
    except UnicodeError:
        s = pykf.tosjis(s, pykf.JIS)
        s = unicode(s, 'cp932')
        s = s.encode('utf-8')
        del m['content-transfer-encoding']
        m.set_payload(s, 'utf-8')


if __name__ == '__main__':
    import sys
    from email import message_from_file
    msg = message_from_file(file(sys.argv[1]))
    process(None, msg, None)
    print msg
