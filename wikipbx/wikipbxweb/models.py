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

import re, os, shutil
from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from wikipbx import logger, utils, sofiautil
from xml.dom import minidom

"""

Notes on model design:

A server can have only one "superuser".  The superuser
CANNOT also be other things like an account admin or
end user.  The root user can add/delete accounts, as well
as login as existing account admins to do administration.

The superuser is just a User/Userprofile with the is_super
flag set to True.  Nothing in the db design ensures the
rule above, it is enforced by the code.

Each Account has one or more account admins.  The account
admin is also an enduser, but just has more privilages.

"""
    
class UserProfile(models.Model):
    """
    Each 'web user', including admins, has a user profile.
    The root user does NOT have a userprofile associated with it.
    """

    # django user
    user = models.OneToOneField(User)

    # which account does this user belong to?
    account = models.ForeignKey("Account", related_name="account")

    def is_acct_admin(self):
        return (self in self.account.admins.all())

    def delete(self):
        logger.debug("deleting userprofile")
        self.user.delete()
        super(UserProfile, self).delete() # Call the "real" delete() method

    def short_email(self):
        """
        get a shortened version of email
        """
        numchars = 10
        if len(self.user.email) <= numchars:
            return self.user.email
        else:
            return "%s.." % self.user.email[:8]


    def form_dict(self):
        retval = {}
        retval['email'] = self.user.email
        retval['first_name'] = self.user.first_name
        retval['last_name'] = self.user.last_name
        retval['is_active'] = self.user.is_active
        return retval
            
    def __str__(self):
        return self.user.email

    class Admin:
        pass


class SipProfile(models.Model):
    """
    Sip profile (sip user agent)

    """

    # every sip profile should have a name.  perfectly valid to
    # use names like internal/external
    name = models.CharField(max_length=50, null=False)
    
    ext_rtp_ip = models.CharField(max_length=100, default="auto")
    ext_sip_ip = models.CharField(max_length=100, default="auto")
    rtp_ip = models.CharField(max_length=100, default="auto")
    sip_ip = models.CharField(max_length=100, default="auto")
    sip_port = models.PositiveIntegerField(unique=True)    
    accept_blind_reg = models.BooleanField(default=False)

    # should freeswitch authorize all INVITE's on this profile?
    # on the internal (5060) profile, this is set to true.  on the
    # external (5080) profile, this is set to false.  
    auth_calls = models.BooleanField(default=False)

    def __str__(self):
        return "sip profile: %s:%s" % (self.ext_rtp_ip, self.sip_port)

    def accept_blind_reg_str(self):
        if self.accept_blind_reg:
            return "True"
        else:
            return "False"

    def get_gateways(self):
        """
        get all gateways in the system assigned to this sip profile
        """
        retval = []
        accounts = Account.objects.all()
        for account in accounts:
            for gateway in account.sofiagateway_set.all():
                if gateway.sip_profile.id == self.id:
                    retval.append(gateway)
        return retval

    def get_aliased_domains(self):
        """
        get all accounts that are aliased to this profile
        """
        accounts = Account.objects.filter(dialout_profile=self,
                                          aliased=True)
        return accounts

    def form_dict(self):

        retval = {}
        retval['name'] = self.name
        retval['ext_rtp_ip'] = self.ext_rtp_ip
        retval['ext_sip_ip'] = self.ext_sip_ip
        retval['rtp_ip'] = self.rtp_ip
        retval['sip_ip'] = self.sip_ip
        retval['sip_port'] = self.sip_port
        retval['accept_blind_reg'] = self.accept_blind_reg
        retval['auth_calls'] = self.auth_calls
        return retval

    class Admin:
        pass
    
class Account(models.Model):

    """
    On a dedicated appliance, there will only be one account
    for the people who bought the appliance.  In other situations
    there might be more than one account, eg, a hosted version
    (wikipbx.com selling hosted accts to the masses)
    """

    # this will be the sofia profile name.  perhaps this field
    # should be merged with name.
    name = models.CharField(max_length=50)
    
    admins = models.ManyToManyField('UserProfile',
                                    related_name="admins")
    enabled = models.BooleanField(default=True)

    # will be returned with directory xml: <domain name="$${domain}">
    # for all endpoints that belong to this account.
    # all sip endpoints for this account MUST use this domain when
    # connecting to the switch.  when endpoints are dialed,
    # this domain is used: eg, sofia/foo/100%foo.com.  perhaps
    # this field should be merged with domain.
    # if left blank, the system falls back to ext_sip_ip.
    domain = models.CharField(max_length=50, unique=True)

    # the profile to use when generating dialstrings for this
    # account.  note that this does not restrict this account
    # to this profile, quite the contrary, since the account will
    # be active (eg, dialplan seved) on all profiles.
    dialout_profile = models.ForeignKey('SipProfile')

    # if this is true, the domain associated with this account
    # will be "aliased" to the default dialout profile, so in other
    # words the domain can be used as a synonym for that profile
    # and instead of dialstring: sofia/external/123@att.com you
    # can use sofia/yourcompany.com/123@att.com and freeswitch
    # will dial out of the external profile (assuming the external
    # profile is the default dialout profile for this account)
    aliased = models.BooleanField(default=True)

    def get_domain(self):
         return self.domain
 
    def short_name(self):
        numchars = 10
        if len(self.name) <= numchars:
            return self.name
        else:
            return "%s.." % self.name[:8]

    def delete(self):
        for admin in self.admins.all():
            admin.delete()
        for userprof in UserProfile.objects.filter(account=self):
            userprof.delete()
        super(Account, self).delete() # Call the "real" delete() method

    def form_dict(self):
        retval = {}
        retval['name'] = self.name
        retval['enabled'] = self.enabled
        retval['domain'] = self.domain
        retval['dialout_profile'] = self.dialout_profile.id
        retval['aliased'] = self.aliased
        return retval
     
    def is_admin(self, userprofile):
        return userprofile in self.admins.all()

    def __str__(self):
        return self.name

    class Admin:
        pass
    

    
class Extension(models.Model):
    """
    An extension, the equivalent of the file-based extensions in
    default_context.xml:

    <extension name="neoconf">
      <condition field="destination_number" expression="^neoconf[-]?([0-9]*)$">
        <action application="set" data="conf_code=$1"/>
        <action application="python" data="neoconf.ivr.prompt_pin"/>
      </condition>
    </extension>
    
    """

    # which account owns this extension?
    account = models.ForeignKey("Account")

    # experimenting with dialplan security ..
    auth_call = models.BooleanField(default=True)

    # a regex expression that will be used to match against the
    # destination number (number called by endpoint)
    # eg: ^neoconf[-]?([0-9]*)$
    dest_num = models.CharField(max_length=75)

    # description, eg, "welcome message"
    desc = models.CharField(max_length=250)

    # the actions in a malformed rootless xml snippet:
    # <action application="set" data="conf_code=$1"/>
    # <action application="python" data="neoconf.ivr.prompt_pin"/>
    # yes, this assumes only basic usage, but in fact _anything_
    # stuck in here will be mirrored into the dialplan result
    # returned from views.xml_dialplan()
    actions_xml = models.TextField()

    # is this a temporary extension?
    is_temporary = models.BooleanField(default=False)

    # is this extension associated w/ a particular endpoint?
    # eg, when user creates them both at the same time
    endpoint = models.ForeignKey("Endpoint", null=True)

    # the priority position of this extension, relative to other extensions.
    # think of the list of extensions as if they were in a a file
    # so the "top" extension corresponds to priority position 0,
    # the one below to 1, etc.  nothing fancy here, just a simple ordering.
    priority_position = models.IntegerField()

    def dest_num_matches(self, destnum2test):
        # TODO: cache compiled regexes
        #matchstr = re.compile(self.dest_num)
        #result = matchstr.search(destnum2test)
        #if (result != None):
        #    return True
        #return False
        groups = re.findall(self.dest_num, destnum2test)
        return groups

    def get_actions_xml_dom(self):
        """
        get a dom object like
        <actions_xml>
        <action application="set" data="conf_code=$1"/>
        <action application="python" data="neoconf.ivr.prompt_pin"/>        
        </actions_xml>
        where everything inside <actions_xml> comes right out
        of the actions_xml field
        """
        xml_text = "<actions_xml>%s</actions_xml>" % self.actions_xml
        dom = minidom.parseString(xml_text)
        return dom

    def get_xml_preview(self):
        """
        get the first X chars of xml for preview purposs
        """
        numchars = 50
        retval = "Error"

        # chop off repetitive head if found
        # <action application="speak" data="cepstral|William.. -->
        # <...="speak" data="cepstral|William.. -->
        retval = re.sub(r'action application', r'...', self.actions_xml)

        if len(retval) > numchars:
            retval = "%s.." % retval[:numchars]
        return retval

    def get_sofia_url(self):
        """
        get the dialable url for this extension, eg,
        sofia/mydomain.com/600@ip:port
        """

        single_expansion = self.get_single_expansion()
        if not single_expansion:
            raise Exception("There is no single expansion for this "
                            "extension: %s" % str(self))
        return sofiautil.extension_url(single_expansion,
                                       self.account)
                                       
        
    def get_single_expansion(self):
        """
        does the destination number for this extension have
        a singl expansion?  
        ^600$ -> 600
        ^\d+$ -> None
        """
        # find what's inside the ^()$, eg, ^600$ -> 600.  600->600
        # optional ^ specified by \^?, followed by any number of
        # anything except $ specified by ([^\$]*), followed
        # by optional $ specified by \$?
        regex = "\^?([^\$]*)\$?"
        groups = re.findall(regex, self.dest_num)
        stuffinside = groups[0]

        # at this point, group will be something like "600", or if
        # self.dest_num is empty, will be an empty string
        # now, find out if its alphanum ONLY, eg, no regex
        # specifiers.  do this by "regexing it against itself".
        # things like 600 will match, whereas things like 
        # '60(2|3)0' will fail.  and things like *98 will blow up *boom*
        try:
            groups = re.findall(stuffinside, stuffinside) 
            if groups:
                # doesnt cover every case, for example..
                # 1?4085400303
                if groups[0] == stuffinside:
                    return stuffinside
                else:
                    return None
            else:
                return None
        except:
            # this will happen in the case of an illegal regex, such as *98  
            return None

    def form_dict(self):
        retval = {}
        retval['dest_num'] = self.dest_num
        retval['desc'] = self.desc
        retval['actions_xml'] = self.actions_xml
        retval['is_temporary'] = self.is_temporary        
        return retval


    def __str__(self):
        return "%s (%s)" % (self.dest_num, self.priority_position)


    class Admin:
        pass

    
class Endpoint(models.Model):
    """
    Each SIP endpoint that will register with the system
    should have an entry here.  Upon creating an SIP endpoint,
    the system should create an extension for that endpoint
    with actions that try to bridge, then go to voicemail.
    """

    # the userid, eg, 4761
    userid = models.CharField(max_length=100)

    # the password they will use to register the endpoint
    password = models.CharField(max_length=100, blank=True)

    # each endpoint _must_ be associated with a single account
    account = models.ForeignKey("Account")

    # each endpoint _may_ be associated with a specific user
    userprofile = models.ForeignKey('UserProfile', null=True)    

    # the ip address it has for its contact field
    contact_addr = models.IPAddressField(blank=True,default="0.0.0.0")

    # Default value. Note that it's not stored in DB anymore.
    is_registered = False

    def get_extensions(self):
        return self.extension_set.all()

    def delete(self):
        extensions = self.extension_set.all()
        for extension in extensions:
            extension.delete()
        super(Endpoint, self).delete() # Call the "real" delete() method
    
    def __str__(self):
        return self.userid

    def form_dict(self):
        retval = {}
        retval['userid'] = self.userid
        retval['password'] = self.password

        return retval

    class Meta:
    	unique_together = (("userid", "account"),)
    
    class Admin:
        pass


class SofiaGateway(models.Model):

    # gateway name
    name = models.CharField(max_length=100, unique=True)

    # Which Sip Profile communication with this gateway will take place on.
    # Typically will be external profile on port 5080
    sip_profile = models.ForeignKey('SipProfile')

    # gateway "owner" even though it is visible/usable by ANY account (for now)
    account = models.ForeignKey('Account')    

    # username for gateway login/authentication
    username = models.CharField(max_length=25)

    # password for gateway login/authentication
    password = models.CharField(max_length=25)

    # proxy host: *optional* same as realm, if blank
    proxy = models.CharField(max_length=50, blank=True)
    
    # register w/ the gateway?
    register = models.BooleanField(default=False)

    # extension for inbound calls: *optional* same as username, if blank
    extension = models.CharField(max_length=50, blank=True)

    # auth realm: *optional* same as gateway name, if blank
    realm = models.CharField(max_length=50, blank=True)

    # domain to use in from: *optional* same as  realm, if blank
    # eg, asterlink.com
    from_domain = models.CharField(max_length=50, blank=True)

    # expire in seconds: *optional* 3600, if blank
    expire_seconds = models.PositiveIntegerField(default=60, null=True)

    # How many seconds before a retry when a failure or timeout occurs -->
    retry_seconds = models.PositiveIntegerField(default=30, null=True)

    # Use the callerid of an inbound call in the from field on outbound calls via this gateway
    # replace the INVITE from user with the channel's caller-id    
    caller_id_in_from = models.BooleanField(default=False)

    # is this gateway accessible to all accounts?  temporary hack until
    # "root gateways" are implemented.
    accessible_all_accts = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    def form_dict(self):
        retval = {}
        retval['name']=self.name
        retval['username']=self.username
        retval['password']=self.password
        retval['proxy']=self.proxy
        retval['register']=self.register
        retval['extension']=self.extension
        retval['realm']=self.realm
        retval['from_domain']=self.from_domain
        retval['expire_seconds']=self.expire_seconds
        retval['retry_seconds']=self.retry_seconds
        retval['caller_id_in_from']=self.caller_id_in_from
        retval['sip_profile']=self.sip_profile.id
        return retval

    class Admin:
        pass


class ServerLog(models.Model):
    """
    Certain failures, like when an error occurs trying to add a CDR
    record when freeswitch calls the webserver, should be logged in
    this table for display on the web GUI.
    """
    account = models.ForeignKey("Account", null=True)
    logtime = models.DateTimeField(null=True)    
    message = models.TextField()    


class EmailConfig(models.Model):
    """
    When the server needs to send email, it uses the per-account email
    configuration or falls back to the per-server configuration, if one exists.
    """
    account = models.ForeignKey("Account", null=True)
    from_email = models.EmailField()
    email_host = models.CharField(max_length=100)
    email_port = models.PositiveIntegerField()
    auth_user = models.CharField(max_length=100, blank=True)
    auth_password = models.CharField(max_length=100, blank=True)

    # whether to use TLS for encrypting communication
    # between wikipbx server and email server.  required
    # for gmail.  at time of writing, only tested with
    # use_tls == True
    use_tls = models.BooleanField()

    def form_dict(self):
        retval = {}
        retval['from_email'] = self.from_email
        retval['email_host'] = self.email_host
        retval['email_port'] = self.email_port
        retval['auth_user'] = self.auth_user
        retval['auth_password'] = self.auth_password
        retval['use_tls'] = self.use_tls
        return retval
    
    class Admin:
        pass


class Ivr(models.Model):

    """
    An IVR script
    """

    # the filename, without the extension.  eg, "default", which
    # will cause the system to look for default.py in the ivr
    # directory
    name = models.CharField(max_length=100)

    # py for python, js for javascript
    language_ext = models.CharField(max_length=20)

    # sofia profile / account this ivr belongs to, will
    # be in ${wikipbx_root}/ivr/${account.name}
    # or if null, it means that its a "global" ivr
    # and will be in ${wikipbx_root}/ivr
    account = models.ForeignKey("Account", null=True)

    def get_language(self):
        ext2langs = {
            'py': 'python',
            'js': 'javascript',
            }
        return ext2langs.get(self.language_ext, "Error")

    def get_action_xml(self):
        action_xml = '<action application="%s" data="%s"/>' % \
                     (self.get_language(), self.get_module_path())
        return action_xml
  
    def get_module_path(self):
        """
        python specific .. get module path
        """
        if self.language_ext == "py":
            if self.account:        
                return "wikipbx.ivr.%s.%s" % (self.account.name,
                                              self.name)
            else:
                return "wikipbx.ivr.%s" % (self.name)
        elif self.language_ext == "js":
            if self.account:        
                return "%s/%s/%s.js" % (settings.INSTALL_SRC,
                                        self.account.name,
                                        self.name)
            else:
                return "%s/%s.js" % (settings.INSTALL_SRC,
                                     self.name)                
        else:
            return "Error"
        
    def script2file(self, ivr_code):
        script_path = self.get_script_path()
        open(script_path, 'w').write(ivr_code)

    def get_script_path(self):
        script_dir = self.get_script_dir()
        script_fn = "%s.%s" % (self.name, self.language_ext)
        script_path = os.path.join(script_dir, script_fn)
        return script_path

    def get_script_dir(self):
        application_root = settings.INSTALL_SRC
        if self.account:
            ivr_root = os.path.join(application_root, "ivr")
            account_ivr_root = os.path.join(ivr_root, self.account.name)
            if not os.path.exists(account_ivr_root):
                os.makedirs(account_ivr_root)
                self.create_module_inits()
            return account_ivr_root
        else:
            ivr_root = os.path.join(application_root, "ivr")
            return ivr_root

    def create_module_inits(self):
        """
        the ivr dir and each subdir needs to have __init__.py
        scripts
        """
        application_root = settings.INSTALL_SRC
        ivr_root = os.path.join(application_root, "ivr")
        ivr_init_path = os.path.join(ivr_root, "__init__.py")
        open(ivr_init_path,'w').write("# placeholder")
        account_ivr_root = os.path.join(ivr_root, self.account.name)        
        account_ivr_init_path = os.path.join(account_ivr_root, "__init__.py")
        open(account_ivr_init_path,'w').write("# placeholder")        
        
    def file2script(self):
        script_path = self.get_script_path()
        return open(script_path, 'r').read()

    def delete(self):
        script_path = self.get_script_path()
        if os.path.exists(script_path):
            os.remove(script_path) 
        super(Ivr, self).delete() # Call the "real" delete() method

    def form_dict(self):
        result = {}
        result['name'] = self.name
        result['language_ext'] = self.language_ext
        result['ivr_code'] = self.file2script()
        return result

    def __str__(self):
        return "%s.%s (id=%s)" % (self.name, self.language_ext, self.id)

    class Admin:
        pass

class Soundclip(models.Model):
    """
    sound clip, stored in /${app_root}/soundclips/${account.name}/%{name}
    TODO: support other file extensions like slin, mp3, ogg, etc
    """
    account = models.ForeignKey("Account")    
    name = models.CharField(max_length=100)
    desc = models.CharField(max_length=100)

    def get_path(self):
        # path to recorded file
        soundclip_root = os.path.join(settings.INSTALL_SRC,
                                      "soundclips",
                                      self.account.name)
        if not os.path.exists(soundclip_root):
            os.makedirs(soundclip_root)

        soundclip_fname = "%s.wav" % self.name
        soundclip_path = os.path.join(soundclip_root, soundclip_fname)
        return soundclip_path
        
    def __str__(self):
        return "%s (id=%s)" % (self.name, self.id)

    class Admin:
        pass


class PhoneContact(models.Model):

    """
    A very lightweight contact database entry that will be stored
    every time someone is dialed out via web dialout.
    """

    # The name of the user/owner of this phone
    name = models.CharField(max_length=100,blank=True)

    # Acceptable forms
    # 14081112222
    # sip:7471122334@proxy01.sipphone.com
    number = models.CharField(max_length=100) 

    # The extension or empty if no extension
    ext = models.CharField(max_length=20,blank=True)

    # The user this phone is associated with.  If phonecontact
    # entered as a result of a web dialout, will be logged in user
    userprofile = models.ForeignKey('UserProfile', null=True)

    # Was this number explicitly entered in phonebook
    # or was it just dialed by user at some point in past?
    is_explicit = models.BooleanField(default=False)

    # Is this phone number private?  If not, it will
    # show up in the global phone book associated with
    # the account
    is_private = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    class Admin:
        pass


class CompletedCall(models.Model):
    """
    every incoming call will be recorded here.  (WARNING:
    this table could get big and slow down the system)
    """

    # account / sip profile this completed call belongs to
    account = models.ForeignKey('Account')

    # uuid
    uuid = models.CharField(max_length=100)
    
    # <caller_id_number> from cdr cml
    caller_id_number = models.CharField(max_length=100)

    # <destination_number> from cdr cml
    destination_number = models.CharField(max_length=100)

    # last part of <chan_name> from cdr xml, eg, if
    # chan_name is sofia/mydomain.com/foo@bar.com, will have foo@bar.com
    chan_name = models.CharField(max_length=100)

    answered_time = models.DateTimeField()
    hangup_time = models.DateTimeField()    

    # entire cdr xml as raw text
    cdr_xml = models.TextField()

    def get_duration_str(self):
        """
        get the duration of the call as an intelligently formatted
        string:
        2 secs
        1 minutes, 5 seconds
        """
        hours = minutes = seconds = 0
        delta = self.hangup_time - self.answered_time
        minutes, seconds = divmod(delta.seconds, 60)
        if minutes and minutes >= 60:
            hours, minutes = divmod(minutes, 60)
        if hours:
            return "%s hours, %s mins, %s seconds" % (hours, minutes, seconds)
        elif minutes:
            return "%s mins, %s seconds" % (minutes, seconds)
        else:
            return "%s seconds" % seconds
    
    class Admin:
        pass


class EventSocketConfig(models.Model):
    """
    <configuration name="event_socket.conf" description="Socket Client">
      <settings>
        <param name="listen-ip" value="127.0.0.1"/>
        <param name="listen-port" value="8021"/>
        <param name="password" value="ClueCon"/>
      </settings>
    </configuration>
    """

    listen_ip = models.IPAddressField()
    listen_port = models.PositiveIntegerField()
    password = models.CharField(max_length=25)

    def form_dict(self):
        result = {}
        result["listen_ip"] = self.listen_ip
        result["listen_port"] = self.listen_port
        result["password"] = self.password
        return result

    class Admin:
        pass

__all__ = (
    'ServerLog', 'UserProfile', 'Account', 'EmailConfig',
    'Endpoint', 'Ivr', 'Soundclip', 'Extension', 'PhoneContact',
    'CompletedCall', 'SipProfile', 'SofiaGateway', 'EventSocketConfig')
