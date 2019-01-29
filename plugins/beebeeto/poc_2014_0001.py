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
            'id': 'poc-2014-0001',
            'name': 'Discuz x3.0 /static/image/common/focus.swf 跨站脚本漏洞 POC',
            'author': '1024',
            'create_date': '2014-08-01',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz', 
            'vul_version': ['x3.0'],
            'type': 'Cross Site Scripting',
            'tag': ['Discuz!', 'xss', 'flash xss'],
            'desc': 'DiscuzX3.0 static/image/common/focus.swf文件存在FlashXss漏洞。',
            'references': ['http://www.ipuman.com/pm6/137/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        flash_md5 = "c16a7c6143f098472e52dd13de85527f"
        file_path = "/static/image/common/focus.swf"
        verify_url = args['options']['target'] + file_path
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
        else:
            args['success'] = False
            return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
