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

import re
import datetime, urllib2

def strip_url_params(url):
    """
    given url:
    
    http://localhost:9000/dashboard/?infomsg=You%20have%20been%20successfully%20logged%20in

    return:

    http://localhost:9000/dashboard/

    """

    parm_start_index = url.find("?")
    sans_parms = url[:parm_start_index]
    return sans_parms



def xml_snippet_no_header(serialized_xml):
    """
    generate an xml snippet suitable for inserting
    (strip off hte <?xml header stuff)

    Test cases:
    content = '<?xml version="1.0" ?><yo>sucks</yo>'
    content = '<?xml version="1.0" ?>\n<yo>sucks</yo>'
    """
    # match anchored at beginning of line, followed by <?xml,
    # followed by any number of any character EXCEPT >, followed
    # by >
    regex = '^(\s*)<\?xml([^>]*)>'
    matchstr = re.compile(regex, re.MULTILINE)
    result = matchstr.search(serialized_xml)
    if (result != None):
        serialized_xml = matchstr.sub("",serialized_xml)
    return serialized_xml
 

def get_duration_str(raw_seconds):
    """
    get the duration as a nicely formatted string:
    2 secs
    1 minutes, 5 seconds
    """
    hours = minutes = 0
    minutes, seconds = divmod(raw_seconds, 60)
    if minutes and minutes >= 60:
        hours, minutes = divmod(minutes, 60)
    if hours:
        return "%s hours, %s mins, %s seconds" % (hours, minutes, seconds)
    elif minutes:
        return "%s mins, %s seconds" % (minutes, seconds)
    else:
        return "%s seconds" % seconds

class DownloadError(Exception):
    """
    This exception is raised if file download fails.
    """

def download_url(url, path=None):
    """
    Fetch the content from a url, write to file or a string.

    @param url: URL to fetch.
    @type url: str.
    @param path: file path to write, None means writing to a string buffer.
    @type path: str.
    @return: string buffer with result or None.
    @raises: DownloadError.
    """
    if path:
        dst = file(path, 'w')
    else:
        dst = StringIO()

    try:
        req = urllib2.Request(url)
        result = urllib2.urlopen(req)
        stringbuffer = []
        while 1:
            data = result.read(1024)
            stringbuffer.append(data)
            if not len(data):
                break
            dst.write(data)
        if path:
            dst.close()
            return None
        else:
            return dst.getvalue()
    except:
        raise DownloadError()

def fetchAndWriteContent(longurl, file2write):
    """ fetch the content from a url, write to given file """
    req = urllib2.Request(longurl)
    fd = urllib2.urlopen(req)
    sinkfd = open(file2write, 'w')
    while 1:
        data = fd.read(1024)
        sinkfd.write(data)
        if not len(data):
            break

def alphanum2numeric(name):
    """
    phone keypad translation of a string ..
    
    bob -> 262 
    """
    letter2num = {"a":2,
                  "b":2,
                  "c":2,
                  "d":3,
                  "e":3,
                  "f":3,
                  "g":4,
                  "h":4,
                  "i":4,
                  "j":5,
                  "k":5,
                  "l":5,
                  "m":6,
                  "n":6,
                  "o":6,
                  "p":7,
                  "q":7,
                  "r":7,
                  "s":7,
                  "t":8,
                  "u":8,
                  "v":8,
                  "w":9,
                  "x":9,
                  "y":9,
                  "z":9}

    result = []
    for letter in name:
        number = letter2num[letter]
        result.append(number)
    return "".join(result)
