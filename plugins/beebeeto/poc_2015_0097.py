#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0097',
            'name': 'Wordpress /example.html jQuery DomXSS漏洞 POC',
            'author': '1024',
            'create_date': '2015-05-08',
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
            'vul_version': ['*'],
            'type': 'Cross Site Scripting',
            'tag': ['WordPress默认模板漏洞', '/example.html XSS 漏洞', 'jQuery 漏洞'],
            'desc': '''
                    该漏洞存在于 WordPress 流行的 Genericons example.html 页面中，
                    默认主题 Twenty Fifteen 及知名插件 Jetpack 都内置了该页面，
                    由于 example.html 使用了老版本存在 DOM XSS 缺陷的 jQuery，且使用不当，
                    导致出现 DOM XSS，这种攻击将无视浏览器的 XSS Filter 防御。
                    ''',
            'references': ['http://linux.im/2015/05/07/jQuery-1113-DomXSS-Vulnerability.html'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = '%s/wp-content/themes/twentyfifteen/genericons/example.html' % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200:
          if 'jquery/1.7.2/jquery.min.js"></script>' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())