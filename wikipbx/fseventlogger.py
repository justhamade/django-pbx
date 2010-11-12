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
Stas Shtin <antisvin@gmail.com>
"""

try:
    import eventsocket
except ImportError:
    print "Please instal eventsocket library from "\
          "http://code.google.com/p/eventsocket/"
    raise

import datetime
from django.conf import settings
from twisted.internet import protocol
from twisted.python import log
from wikipbx import xmlutil
from wikipbx.wikipbxweb.models import Endpoint, Account, EventSocketConfig


class InboundProtocol(eventsocket.EventProtocol):
    def debug(self, msg):
        if self.debug_enabled:
            log.msg(msg)
            
    def authSuccess(self, ev):
        self.eventplain(
            'CUSTOM sofia::register sofia::expire sofia::unregister')

    def authFailure(self, failure):
        log.msg("Authentication failed, check your credentials!\n%s" % str(failure))
        self.factory.continueTrying = False
        return failure
        
    def eventplainSuccess(self, ev):
        log.msg("Freeswitch login succeeded")

    def eventplainFailure(self, failure):
        self.factory.continueTrying = False
        self.exit()

    def get_sofia_vals(self, data):
        # UNUSED
        profile_name = data.get('profile_name', None)
        from_user = data.get('from_user', None)
        contact = data.get('contact', None)

        if not from_user:
            # blah - there is an inconstency in fs, sometimes returns
            # 'from-user' and other times returns 'user'
            from_user = data.get('user', None)
            
        return profile_name, from_user, contact

    def get_sofia_endpoint(self, profile_name, from_user):
        # UNUSED
        account = Account.objects.get(name=profile_name)
        endpoints = Endpoint.objects.filter(account=account, userid=from_user)
        if endpoints:
            endpoint=endpoints[0]
            return endpoint
        else:
            self.debug(
                "No endpoint in account: %s with userid: %s" %
                (account, from_user))

    

class EventSocketInboundFactory(protocol.ReconnectingClientFactory):
    protocol = InboundProtocol
    
    def __init__(self, password, debug):
        self.password = password
        self.debug = debug        

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.factory = self
        proto.debug_enabled = self.debug
        return proto
