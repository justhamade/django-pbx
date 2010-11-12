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

NOTE: this class is still in use (by xmlconfig) although the
main function to generate dialplan is dead.  just the helpers
remain here.

"""
import re
from wikipbx import logger
from wikipbx.wikipbxweb.models import *


def group_substitutions(raw_attr, groups):
    """
    Given:

    raw_attr=$1
    and
    groups=['18005551212']

    Return '18005551212'

    Example groups:

    [('18004664411', '00')]

    See test case: test_group_substitutions()
    """

    # no groups, nothing to do .
    if not groups:
        return raw_attr

    counter = 1
    for outergroup in groups:
        if is_array_or_tuple(outergroup):
            for innergroup in outergroup:
                # eg, $1 if counter is 1, etc
                matcher = re.compile('\$%s' % counter, re.I)
                raw_attr = matcher.sub(innergroup,raw_attr)
                counter += 1
        else:
            # eg, $1 if counter is 1, etc
            matcher = re.compile('\$%s' % counter, re.I)
            raw_attr = matcher.sub(outergroup,raw_attr)
            counter += 1

    return raw_attr

def test_group_substitutions():
    groups = [('18004664411', '00')]
    result = group_substitutions(raw_attr, groups)
    assert(result == 'yo18004664411woot00')    
    groups = [('18004664411'), ('11')]
    result = group_substitutions(raw_attr, groups)
    assert(result == 'yo18004664411woot11')
    groups = ['18004664411', '22']
    result = group_substitutions(raw_attr, groups)
    assert(result == 'yo18004664411woot22')

def is_array_or_tuple(thing):
    if type(thing) == type((0,1)):
        return True
    elif type(thing) == type([0,1]):
        return True
    else:
        return False

def find_extension(account, dest_num):
    """
    find the first matching extension.  returns a tuple,
    (ext, groups), where groups is an array of regex groups
    which can be used for replacing $1 $2 etc found in
    the xml
    """
    exts = Extension.objects.filter(account=account)
    exts = exts.order_by("priority_position")
    for ext in exts:
        groups = ext.dest_num_matches(dest_num)
        if groups:
            logger.debug("|%s| == |%s| (MATCH!)" % (dest_num, ext.dest_num))
            gateway_security_check(account, ext)
            return (ext, groups)
        else:
            logger.debug("|%s| != |%s|" % (dest_num, ext.dest_num))
    return (None, None)

def gateway_security_check(account, extension):
    """
    does this extension contain action xml that attempts to dial
    out of a gateway not owned by this account?
    If not, return None.  Otherwise, raise an exception.
    """
    actions_xml = extension.actions_xml
    matchstr = re.compile("sofia/gateway/([^\/]*)")
    result = matchstr.search(actions_xml)
    if not result:
        # dialplan does not try to dial out of any gateways
        return
    gateway_name = result.group(1)

    # find gateway with this name
    gateways = SofiaGateway.objects.filter(name=gateway_name)
    if not gateways:
        raise Exception("No gateway found with name: %s" % gateway_name)
    gateway = gateways[0]

    # is it accessible to all accounts?
    if gateway.accessible_all_accts:
        return

    # is it owned by this account
    if gateway.account != account:
        raise Exception("You are not allowed to use gateway %s from "
                        "account %s, as it is owned by by %s" %
                        (gateway, account, gateway.account))
        
