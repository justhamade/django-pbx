""" 
WikiPBX web GUI front-end for FreeSWITCH <www.freeswitch.org>
Copyright (C) 2007, Branch Cut <www.branchcut.com>
License Version: MPL 1.1
"""

import os
os.environ['DJANGO_SETTINGS_MODULE']='wikipbx.settings'

from freeswitch import *
from wikipbx.wikipbxweb.models import *

import wikipbx.ivr.baseivr
reload(wikipbx.ivr.baseivr)
from wikipbx.ivr.baseivr import BaseIvr

import datetime, sys, os

class SoundclipRecorder(BaseIvr):

    def __init__(self, session):
        super(SoundclipRecorder, self).__init__(session)        
        self.tts_voice = "william"
        self.session.set_tts_parms("cepstral", self.tts_voice)

    def main(self):

        if self.empty("name") or self.empty("desc"):
            console_log("error", "Soundclip recorder not passed name/desc")
            self.session.speak("Sorry, the soundclip recorder had an error. "
                               "Missing name or description variables. "
                               "Error code 103")                
            
        self.soundclip_name = self.session.getVariable("name")
        self.soundclip_desc = self.session.getVariable("desc")

        soundclips = Soundclip.objects.filter(name=self.soundclip_name,
                                              account=self.account)

        if not soundclips:
            soundclip = Soundclip(name=self.soundclip_name,
                                  desc=self.soundclip_desc,
                                  account=self.account)
        else:
            soundclip = soundclips[0]
            # update the description in case it changed
            soundclip.desc = self.soundclip_desc

        soundclip.save()

        # play beep
        self.session.answer()
        self.playbeep()

        # sleep, otherwise we hear the beep in the recording 
        self.session.execute("sleep", "500")

        # path to recorded file
        soundclip_path = soundclip.get_path()
        
        max_len = 360
        silence_threshold = 500
        silence_secs = 5
        self.session.recordFile(soundclip_path,
                                max_len,
                                silence_threshold,
                                silence_secs)

        self.session.speak("Your sound clip has been recorded.  Goodbye")
        



def handler(session, args):
    screcorder = SoundclipRecorder(session)
    screcorder.main()
