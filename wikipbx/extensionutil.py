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

from wikipbx.wikipbxweb.models import *
from wikipbx.wikipbxweb.models import SipProfile
from django.conf import settings
import random
import os

def get_temp_ext(vardict, action, tempname, account):
    """
    create a temporary extension in the database.
    started out as a workaround for calling python scripts
    with arguments (eg, the extension sets channel variables).

    @vardict - will all be set as channel variables
    @action - the last line of the extension, basically an ivr
    @tempname - to help prevent collision, eg, 'soundclip'
    @account - the account this extension will belong to

    Example extension action xml:

    <action application="set" data="foo=bar"/>
    <action application="python" data="wikipbx.ivr.test.main"/>
    """

    # create a dest_num
    counter = 0
    while counter < 1000000000:
        number2try = random.randint(1000000,9999999)
        dest_num = "%s-%s" % (tempname, number2try)            
        dest_num_dialplan = "^%s$" % dest_num
        matches = Extension.objects.filter(account=account,
                                           dest_num=dest_num)
        if matches:
            # drats, already used ..
            continue
        break
        counter += 1
    

    # generate the actions_xml statements that set variables
    actions_xml = ""
    for channelvar_name, channelvar_val in vardict.items():
        line = '<action application="set" data="%s=%s"/>\n' % (channelvar_name,
                                                               channelvar_val)
        actions_xml += line
    actions_xml += "%s\n" % action

    # create extension
    priority = new_ext_priority_position(account)    
    ext = Extension(account=account,
                    dest_num=dest_num,
                    actions_xml=actions_xml,
                    priority_position=priority,                    
                    is_temporary=True)
    ext.save()

    return dest_num

def endpoint_wizard(endpoint, extension_action):
    """
    @param endpoint - the Endpoint object
    @param extension_action - "bridge" or "bridge_vm"
    """

    # currently just grabs the "first" profile.  what should this be?
    sip_profile = SipProfile.objects.all()[0]  # fixme
    
    # eg, sofia/test/4761%pbx.foo.com if a domain is set
    # or sofia/test/4761%192.168.1.204 if no domain set
    #bridge_data = "sofia/%s/%s%%%s" % (endpoint.account.name,
    bridge_data = "sofia/%s/%s%%%s" % (sip_profile.name,
                                       endpoint.userid,
                                       endpoint.account.get_domain())

    xml = create_bridge_action(extension_action, bridge_data, endpoint)
    return xml

def create_bridge_action(extension_action, bridge_data, endpoint):
    """
    @param bridge_data - eg, sofia/test/4761%192.168.1.204
    @param extension_action - "bridge" or "bridge_vm"
    """
    xml = "Error"
    if extension_action == "bridge":
        xml = ('<action application="bridge" data="%s"/>' % bridge_data)
    elif extension_action == "bridge_vm":
        xmla = []
        set = '<action application="set"'
        py = '<action application="python"'
        xmla.append('%s data="call_timeout=30"/>' % set)
        xmla.append('%s data="continue_on_fail=true"/>' % set)
        xmla.append('%s data="hangup_after_bridge=true"/>' % set)
        xmla.append('<action application="bridge" data="%s"/>' % bridge_data)
        if extension_action == "bridge_vm":
            xmla.append('<action application="voicemail" data="default ${domain_name} ${dialed_extension}"/>')
        xml = "\n".join(xmla)
    else:
        raise Exception("Unknown extension action: %s" % extension_action)

    return xml

def new_ext_priority_position(account):
    """
    when creating a new extension, get the next available
    priority position at end of list
    """
    # find the greatest priority position so far
    exts = Extension.objects.filter(account=account)
    if not exts:
        return 0
    exts = exts.order_by("-priority_position")
    greatest_pp = exts[0].priority_position
    return greatest_pp + 1


def reset_priority_position(account, extension, direction):
    """
    set given extension as top extension (position priority 0)
    """
    exts = Extension.objects.filter(account=account)
    exts = exts.order_by("priority_position")
    if not exts or len(exts) <= 1:
        return
    extlist = [x for x in exts]
    extlist.remove(extension)
    if direction == "highest":
        extlist.insert(0, extension)
    elif direction == "lowest":
        extlist.append(extension)        
    else:
        raise Exception("Unknown direction: %s" % direction)    

    counter = 0
    for ext in extlist:
        ext.priority_position = counter
        ext.save()
        counter += 1

def bump_priority_position(account, extension, direction):
    exts = Extension.objects.filter(account=account)
    exts = exts.order_by("priority_position")    
    if not exts or len(exts) <= 1:
        return
    extlist = [x for x in exts]
    curindex = extlist.index(extension)
    extlist.remove(extension)
    if direction == "raise":
        newindex = curindex - 1
    elif direction == "lower":
        newindex = curindex + 1
    else:
        raise Exception("Unknown direction: %s" % direction)
    extlist.insert(newindex, extension)
    counter = 0
    for ext in extlist:
        ext.priority_position = counter
        ext.save()
        counter += 1

def get_templates(account):
    
    templates = {}
    
    bridge_action = '<action application="bridge"'

    # remote sip endpoint
    templates['sip_url'] = '%s data="sofia/%s/REPLACE@THISADDR.com"/>' % \
                           (bridge_action, account.name)

    # echo
    welcome_echo = os.path.join(settings.INSTALL_ROOT,
                                "soundclips",
                                "welcome_echo.wav")
    
    templates['echo'] = ('<action application="answer"/>'
                         '<action application="playback" data="%s"/>'
                         '<action application="echo"/>' % welcome_echo)

    # gateway dialout
    gateways = account.sofiagateway_set.all()
    if gateways:
        gwname = gateways[0].name
    else:
        gwname = "YOURGATEWAYNAME"
    templates['gateway'] = '%s data="sofia/gateway/%s/$1"/>' % \
                           (bridge_action, gwname)

    # conference
    templates['conference'] = '<action application="conference" data="%s_ARBITRARY_CONF_NAME"/>' % account.name

    # play
    templates['playback'] = ('<action application="playback" data="%s"/>' %
                             welcome_echo)

    # speak
    import random
    number = random.randint(0,1)
    if number == 1:
        voice = "William"
    else:
        voice = "Allison-8kHz"
    templates['speak'] = '<action application="speak" data="cepstral|%s|hello world"/>' % voice

    # voicemail 
    templates['mod_voicemail_play'] = '<action application="answer"/><action application="sleep" data="1000"/><action application="voicemail" data="check default ${domain_name}"/>'

    templates['mod_voicemail_record'] = '<action application="answer"/><action application="sleep" data="1000"/><action application="voicemail" data="default ${domain_name} ${dialed_extension}"/>'

    # transfer
    templates['transfer'] = '<action application="transfer" data="REPLACE_WITH_DEST_EXTESION"/>'

    # park
    templates['park'] = '<action application="park"/>'

    # lua ivr
    templates['lua_ivr'] = '<action application="lua" data="script.lua"/> <!-- try putting your script in /usr/local/freeswitch/scripts -->'

    # python ivr
    templates['python_ivr'] = '<action application="python" data="wikipbx.ivr.echotest"/>'

    # javascript ivr
    ivr_root = os.path.join(settings.INSTALL_SRC, "ivr")
    tmplt = '<action application="javascript" data="%s/%s.your_ivr.js"/>'
    templates['javascript_ivr'] = tmplt % (ivr_root, account.name)

    # sip endpoint -- just info message
    templates['sip_endpoint'] = 'To add an extension that connects to a SIP endpoint, choose SIP Endpoint radio button above!'
    
    return templates
