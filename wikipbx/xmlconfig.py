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
from xml.dom.ext import PrettyPrint
from xml.dom import minidom
from wikipbx.wikipbxweb.models import *
from wikipbx.wikipbxweb.models import SipProfile
from wikipbx import dialplanbuilder
from django.template import Context, Template, loader
from wikipbx import logger
from django.conf import settings

def xml_cdr_config():
    """
    generate xml_cdr config xml by rendering template
    (freeswitchxml/xml_cdr.conf.xml) with data in database 
    """
    t = loader.get_template('xml_cdr.conf.xml')

    url = "%s/add_cdr/" % settings.FREESWITCH_URL_PORT
    
    c = Context({"url": url,
                 "log_dir": settings.CDR_LOG_DIR,
                 "err_log_dir": settings.CDR_ERR_LOG_DIR})
    return t.render(c)


def event_socket_config():
    """
    generate event socket config.  freeswitch uses this config to
    determine which ip/port to listen on for incoming event socket
    connections.  also determines username/password it will accept
    for authenticating users that try to connect.
    """

    t = loader.get_template('event_socket.conf.xml')

    esconfig = EventSocketConfig.objects.all()[0]

    c = Context({"listen_ip": esconfig.listen_ip,
                 "listen_port": esconfig.listen_port,
                 "password": esconfig.password})

    return t.render(c)


def sofia_config():
    """
    generate xml config for sofia (sip stack) configuration.
    """
    t = loader.get_template('sofia.conf.xml')
    sipprofiles = SipProfile.objects.all()
    accounts = Account.objects.filter(enabled=True)
    c = Context({"sipprofiles": sipprofiles, "accounts":accounts})
    return t.render(c)

def dialplan_entry(request):

    #1. use the sip_to_port to lookup the SofiaProfile
    #2. get Account from SofiaProfile

    # find all extensions that have a matching
    # destination number

    if request.POST.has_key('destination_number'):
        # works in fs rev 5834
        dest_num = request.POST['destination_number'] 
    elif request.POST.has_key('Caller-Destination-Number'):
        # works in fs rev 7511
        dest_num = request.POST['Caller-Destination-Number'] 
    else:
        raise Exception("No destination_number given")

    # FINISH THIS
    if not request.POST.has_key('variable_sofia_profile_name'):
        raise Exception("POST request did not contain header: variable_sofia_profile_name")
    profile_name = request.POST['variable_sofia_profile_name'] 
    sipprofiles = SipProfile.objects.filter(name=profile_name)
    if not sipprofiles:
        raise Exception("No SipProfile found with name: %s" % profile_name)
    sipprofile = sipprofiles[0]
    
    # find account
    account = find_account_dialplan_request(request)

    # get extension 
    extension, groups = dialplanbuilder.find_extension(account, dest_num)
    if not extension:
        raise Exception('Extension %s not found' %
                        dest_num)

    
    # do we need to authorize the call?
    call_needs_auth = check_call_needs_auth(extension, request)
    
    # get the actions xml snippet input by the user in the gui
    actions_xml = extension.actions_xml

    # substitute placeholders, eg, $1 -> 18005551212
    # TODO: only do substitution within each "data" attribute, not over
    #       entire xml snippet
    actions_xml = dialplanbuilder.group_substitutions(actions_xml, groups)

    # render template
    if call_needs_auth:
        t = loader.get_template('dialplan_auth_challenge.xml')
    else:
        t = loader.get_template('dialplan.xml')
    c = Context({"extension": extension,
                 "processed_actions_xml": actions_xml,
                 "dialed_extension": dest_num})
    return t.render(c)

def find_account_dialplan_request(request):
    """
    given a freeswitch request for a dialplan, find out
    which account should be used
    """

    # look for variable_domain_name, currently the only time this
    # is known to be useful is when initiating call via web gui
    if request.POST.has_key('variable_domain_name'):
        domain_name = request.POST['variable_domain_name'] 
        accounts = Account.objects.filter(domain=domain_name)
        if accounts:
            return accounts[0]
        
    # next look at sip_req_host
    if not request.POST.has_key('variable_sip_req_host'):
        msg = "POST request did not contain header: variable_sip_req_host"
        raise Exception(msg)
    request_host = request.POST['variable_sip_req_host'] 
    accounts4domain = Account.objects.filter(domain=request_host)
    if len(accounts4domain) == 0:
        raise Exception("No accounts found with  domain: %s" % request_host)
    elif len(accounts4domain) == 1:
        account = accounts4domain[0]
    else:
        msg = "Multiple accounts found with domain: %s" %  request_host
        raise Exception(msg)

    return account


def check_call_needs_auth(extension, request):
    """
    in the context of generating dialplan xml for freeswitch,
    decide if we need to first authorize the caller before
    generating the actual extension.  if the extension in
    the db has the auth_call flag set, then we check the
    request to see if it is already authd.  If not, we return
    special dialplan xml that first challenges and then
    redirects back into the dialplan back to the extension.
    """
    call_needs_auth = True

    # don't require auth for temporary extensions.  without this
    # the Test button on the endpoints page is broken
    if extension.is_temporary:
        return False
    
    if extension.auth_call:
        # extension has auth_call flag, unless already authd need 2 challenge
        # 'variable_sip_authorized': ['true']
        if request.POST.has_key('variable_sip_authorized'):
            val = request.POST['variable_sip_authorized']
            if val and val.lower() == "true":
                call_needs_auth = False
        else:
            # call not auth'd already, need to challenge
            call_needs_auth = True            
        pass
    else:
        # the extension doesn't have the auth_call flag, no need to challenge
        call_needs_auth = False
    return call_needs_auth

def directory(request):
    """
    handle all directory requests
    """

    if request.POST.has_key('domain'):
        """
        when freeswitch is trying to authenticate an endpoint, it passes the domain
        parameter.  so when we see that we assume that it wants a particular user's
        information such as its password. 
        """
        logger.info("directory_user")
        return directory_user(request)
    else:
        """
        when freeswitch sees a <domains> tag in a profile definition (as used for
        aliasing a domain to a sip profile and telling freeswitch to load all
        gateways contained in a directory), then it will call wikipbx with a
        request that does NOT have the domain parameter. 
        """
        logger.info("directory_profile_parse")
        return directory_profile_parse(request)

    
def directory_profile_parse(request):
    """
    freeswitch is parsing a sip profile and saw a <domains><domain> tag and
    wants information on a particular domain.  Params will look like:

    key_name: ['name']
    key_value: ['yourcompany.com']
    """
    
    t = loader.get_template('directory_user.conf.xml')

    key_name = request.POST["key_name"]
    if key_name != "name":
        raise Exception("key_name != name")

    domain = request.POST["key_value"]
    accounts = Account.objects.filter(domain=domain)
    if not accounts:
        raise Exception("No account found with domain name: %s" % domain)
    account = accounts[0]
    
    c = Context({"account": account})

    return t.render(c)

    
def directory_user(request):
    """
    generate xml config for a "directory user".  when a sip endpoint
    tries to register, freeswitch will make an http request with
    some metadata about the user trying to register.  then we lookup
    in our user database and try to find that user, and return xml.

    Example request fs rev 5834:

    'key_value': ['192.168.1.204']
    'key_name': ['name']
    'section': ['directory']
    'domain': ['192.168.1.204']
    'profile': ['foo']    
    'tag_name': ['domain']
    'user': ['4761']
    'ip': ['192.168.1.200']

    Example request fs rev 7511:


    'ip': ['192.168.1.70']
    'key_value': ['192.168.1.101']
    'sip_auth_realm': ['192.168.1.101']
    'key_name': ['name']
    'section': ['directory']
    'hostname': ['spider']
    'sip_auth_method': ['REGISTER']
    'sip_user_agent': ['Linksys/SPA2002-3.1.9(d)']
    'sip_auth_qop': ['auth']
    'sip_auth_username': ['100']
    'tag_name': ['domain']
    'sip_auth_nonce': ['237c9962-3ad8-4e79-807e-f63a4396a999']
    'user': ['100']
    'key': ['id']
    'sip_profile': ['192.168.1.101']
    'action': ['sip_auth']
    'domain': ['192.168.1.101']
    'sip_auth_nc': ['00000002']
    'sip_auth_cnonce': ['8a511ce']
    'sip_auth_response': ['978dc8d62712762f50357f5c61b04113']
    'sip_auth_uri': ['sip:192.168.1.101:5072']
    
    WikiPBX returns:

    <domain name="192.168.0.58">
        <user id="2760">
            <params>
                <param name="password" value="foo" />
            </params>
        </user>
    </domain>
    
    """


    t = loader.get_template('directory_user.conf.xml')

    if request.POST.has_key('profile'):
        # works in fs rev 5834
        profile_name = request.POST['profile']
    elif request.POST.has_key('sip_profile'):
        # works in fs rev 7511
        profile_name = request.POST['sip_profile']
    else:
        # TODO: make this error msg available in front-end gui
        profile_name = None
    
    domain = request.POST['domain']

    if not request.POST.has_key('user'):
        logger.info("FreeSWITCH is requesting entire directory for "
                    "domain: %s but this request is being ignored as this "
                    "type of directory request is not yet supported by "
                    "WikiPBX.  Not known to cause bugs. " % domain)
        return None
                    
    user = request.POST['user']

    if domain:
        accounts = Account.objects.filter(domain=domain)
    else:
        raise Exception("No domain, cannot lookup account")
        
    if not accounts:
        # TODO: make this error msg available in front-end gui
        raise Exception("No account found for domain: %s" % domain)
    else:
        account = accounts[0]

    endpoints = Endpoint.objects.filter(account=account,
                                        userid=user)
    if not endpoints:
        # TODO: make this error msg available in front-end gui
        raise Exception("No endpoint found with userid: %s in account: %s" % \
                        (user, account))
    else:
        endpoint = endpoints[0]

    # make sure domain that the endpoint 'came in on' matches what
    # we have in the database (or the sip_ext_ip) if no domain is set
    if domain != endpoint.account.get_domain():
        # TODO: make this error msg available in front-end gui
        raise Exception("SIP endpoint trying to register with: %s, but that "
                        "does not match the domain in the db: %s " % \
                        (domain, endpoint.account.get_domain()))

    logger.info("endpoint: %s" % endpoint)
    c = Context({"account": account,
                 "endpoint": endpoint})

    return t.render(c)
    
