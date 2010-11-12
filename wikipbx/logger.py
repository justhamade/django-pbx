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

import log4py
import traceback
import StringIO

"""
Log levels:

    LOGLEVEL_NONE
    LOGLEVEL_ERROR
    LOGLEVEL_NORMAL
    LOGLEVEL_VERBOSE
    LOGLEVEL_DEBUG
    """

logobj = log4py.Logger().get_instance()
logobj.set_loglevel(log4py.LOGLEVEL_DEBUG)
#logobj.set_loglevel(log4py.LOGLEVEL_NORMAL)
#logobj.set_loglevel(log4py.LOGLEVEL_VERBOSE)

# use stderr instead of stdout
logobj.remove_all_targets()
logobj.set_target(log4py.TARGET_SYS_STDERR)
logobj.set_formatstring(log4py.FMT_SHORT)


def info(*messages):
    logobj.info(*messages)

def debug(*messages):
    logobj.debug(*messages)

def error(*messages):
    logobj.debug(*messages)
    fp = StringIO.StringIO()
    traceback.print_exc(file=fp)
    message = fp.getvalue()
    messageslist = list(messages)
    messageslist.append("\n")
    messageslist.append(message)
    logobj.error(*messageslist)

def warn(*messages):
    logobj.warn(*messages)

