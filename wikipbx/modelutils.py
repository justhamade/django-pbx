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
from wikipbx import extensionutil

def post_create_endpoint(endpoint, extension_num, extension_desc,
                         extension_action):
    """
    after creating an endpoint, create an extension
    that dials to that endpoint
    """
    xml = extensionutil.endpoint_wizard(endpoint, extension_action)
    dest_num = extension_num
    priority = extensionutil.new_ext_priority_position(endpoint.account)
    extension = Extension(account=endpoint.account,
                          desc=extension_desc,
                          dest_num=dest_num,
                          actions_xml=xml,
                          priority_position=priority,
                          endpoint=endpoint)
    extension.save()


def pre_delete_endpoint(endpoint):
    """
    delete the endpoint extension
    """
    account = endpoint.account
    dest_num = "^%s$" % endpoint.userid    
    endpoint_extensions = Extension.objects.filter(account=account,
                                                   dest_num=dest_num)
    if not endpoint_extensions:
        return

    endpoint_extension = endpoint_extensions[0]
    endpoint_extension.delete()


