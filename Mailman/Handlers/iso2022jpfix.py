#
import pykf

def process(mlist, msg, msgdata):
    if msg.get_content_type() == 'text/plain':
       if msg.get_content_charset().lower() == 'iso-2022-jp':
           m = msg
       else:
           return
    else:
       for m in msg.walk():
           if m.get_content_type() == 'text/plain' and\
              m.get_content_charset().lower() == 'iso-2022-jp':
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
        m.set_payload(s)
        del m['content-transfer-encoding']
        m.set_charset('utf-8')
        # debug
        print m.get_content_charset()

if __name__ == '__main__':
    import sys
    from email import message_from_file
    msg = message_from_file(file(sys.argv[1]))
    process(None, msg, None)
    print msg
