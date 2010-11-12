#!/usr/bin/env python

""" 
WikiPBX web GUI front-end for FreeSWITCH <www.freeswitch.org>
Copyright (C) 2007, Branch Cut <www.branchcut.com>

Version: MPL 1.1

The contents of this file are subject to the Mozilla Public License Version
1.1 (the "License"); you may not use this file except in compliance with
the License. You may obtain a copy of the License at
http://www.mozilla.org/MPL/

Software distributed under the License is distributed on an "AS IS" basis,
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
for the specific language governing rights and limitations under the
License.

The Original Code is - WikiPBX web GUI front-end for FreeSWITCH

The Initial Developer of the Original Code is
Traun Leyden <tleyden@branchcut.com>
Portions created by the Initial Developer are Copyright (C)
the Initial Developer. All Rights Reserved.

Contributor(s): 
"""

import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'wikipbx.settings'

import time, random, datetime
import sys, os, urllib2, urlparse
from email.MIMEText import MIMEText
from email.MIMEImage import MIMEImage
from email.MIMEMultipart import MIMEMultipart
import email, re
import smtplib

from wikipbx.wikipbxweb.models import *

class HtmlMail:
    """
    Allows fine control so that image url's and text are passed
    in as parameters
    """
    def __init__(self, msg_body, server_host, server_port,
                 encoding="iso-8859-1"):
        self.server_port=server_port
        self.server_host=server_host
        self.msg_body = msg_body        
        self.encoding=encoding
        self.img_c=0

    def set_log(self,log):
        self.log=log

    def get_msg(self):

        msg_body = "<p>"
        msg_body += self.msg_body
        msg_body += "</p>"

        msg=MIMEMultipart("related")

        tmsg=MIMEText(msg_body, "html", self.encoding)
        msg.attach(tmsg)
            
        return msg


def acct_send(account, recipients, subject, msg_body):
    """
    gets information from account and calls underlying send
    """
    emailconfigs = EmailConfig.objects.filter(account=account)
    if not emailconfigs:
        msg = "Sorry, no email servers configured for this account"
        raise Exception(msg)

    emailconfig = emailconfigs[0]
    send(recipients=recipients,
         subject=subject,
         msg_body=msg_body,
         server_host=account.ext_sip_ip,
         server_port=account.server.http_port,
         from_email=emailconfig.from_email,
         email_host=emailconfig.email_host,
         email_port=emailconfig.email_port,
         auth_user=emailconfig.auth_user,
         auth_password=emailconfig.auth_password,
         use_tls=emailconfig.use_tls)


def send(recipients, subject, 
         msg_body, server_host, server_port,
         from_email, email_host, email_port, auth_user,
         auth_password, use_tls):

    """
    warning: if multiple recips are specified, they will
    all be able to see eachother's email!!
    @param top_body - the html text above pictures
    @param bottom_body - the html text below pictures
    @param server_host - server host for voicemail page linkback purposes
    @param server_port - server port for voicemail page linkback purposes     
    """
    from django.conf import settings
    
    hm=HtmlMail(msg_body=msg_body,
                server_host=server_host,
                server_port=server_port)
    msg=hm.get_msg()

    msg["Subject"]=subject
    msg["From"]= from_email
    msg['To'] = ', '.join(recipients)

    try:
        random_bits = str(random.getrandbits(64))
    except AttributeError: # Python 2.3 doesn't have random.getrandbits().
        random_bits = ''.join([random.choice('1234567890') for i in range(19)])

    msg['Message-ID'] = "<%d.%s@%s>" % (time.time(), random_bits, "test")

    server = smtplib.SMTP(email_host, int(email_port))
    if use_tls:
        server.ehlo(email_host)
        server.starttls()
    else:
        # this code has NOT been tested when use_tls is false
        pass
    server.ehlo(email_host)
    if auth_user:
        server.login(auth_user, auth_password)
    server.sendmail(from_email, recipients, msg.as_string())

    try:
        server.close() # with .quit(), at least smtp.gmail.com complains
    except:
        raise    
    

if __name__ == "__main__":

    if sys.argv[1] == "gmail_html":
        msg_body = '<h2>New voicemail!</h2><br>'
        send(recipients=["foo@bar.com",
                         "baz@bar.com"],
             subject="New Voicemail",
             msg_body=msg_body,
             server_host="192.168.1.202",
             server_port="8086",
             from_email="You <you@yourcompany.com>",
             email_host="smtp.gmail.com",
             email_port=587,
             auth_user="you@yourcompany.com",
             auth_password="password",
             use_tls=True)
