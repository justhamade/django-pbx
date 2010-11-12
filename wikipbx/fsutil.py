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

import ESL, sys, os, random
from django import http
from wikipbx.wikipbxweb.models import EventSocketConfig
from wikipbx.wikipbxweb.models import SipProfile
from wikipbx import logger

def stop():

    # this starting / stopping from web interface like this
    # was really a lame idea.  disable
    #cmd = "/etc/init.d/freeswitch stop"
    #os.system(cmd)

    #cmd = ("ps auxww | grep -i freeswitch | grep -v grep "
    #       "| grep -iv screen | awk '{print $2}' | xargs kill -9")
    #os.system(cmd)

    # TODO: find usages of stop() and remove them
    
    pass

def start():

    # this starting / stopping from web interface like this
    # was really a lame idea.  disable
    #cmd = "/etc/init.d/freeswitch start"
    #x = os.system(cmd)
    #signal = x & 0xFF
    #exitcode = (x >> 8) & 0xFF
    #return exitcode


    # TODO: find usages of stop() and remove them
    
    pass

def restart():
    stop()
    return start()

def get_fs_connections():
    """
    Get all available ESL connections.
    """
    logger.info("get_fs_connections()")
    sockets = EventSocketConfig.objects.all()
    if sockets:
        logger.info("%s eventsockets" % len(sockets))
    else:
        logger.info("no eventsockets")
        
    for socket in sockets:
        logger.info("creating eslconnection")
        yield ESL.ESLconnection(
            socket.listen_ip, str(socket.listen_port),
            socket.password)

    logger.info("get_fs_connections() done")

def get_fs_connection():
    """
    Get a single ESL connection. Selected randomly.
    """
    return random.choice(list(get_fs_connections()))

def restart_profiles(success_msg, error_msg, return_url):
    logger.info("restart_profiles called")

    for connection in get_fs_connections():
        try:                    
            #connection.sendRecv(
            #    ("api sofia profile %s restart" % account.name)
            #    if account else ("api sofia restart profile all"))
            for sipprofile in SipProfile.objects.all():
                connection.sendRecv("api sofia profile %s restart" % sipprofile.name)
        except Exception, e:
            msg = error_msg + str(e)
        else:
            msg = success_msg
        return http.HttpResponseRedirect("%s?infomsg=%s" % (return_url, msg))

    else:
        msg = ("No EventSocket configured in WikiPBX.  Cannot connect "
               "to freeswitch over event socket")
        return http.HttpResponseRedirect("%s?infomsg=%s" % (return_url, msg))

    logger.info("restart_profiles done")

    
    
__all__ = (
    'start', 'stop', 'restart', 'get_fs_connections', 'get_fs_connection',
    'restart_profiles')
