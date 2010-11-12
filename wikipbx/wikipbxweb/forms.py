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
import re
from django import forms
from django.core.validators import validate_ipv4_address
from django.forms import widgets

__all__ = (
    'ConfigMailserverForm', 'TestMailserverForm', 'ExtensionForm',
    'SoundclipForm', 'IvrForm', 'UserProfileForm',
    'UserProfileEditForm', 'RootUserForm', 'AccountAndAdminForm',
    'AccountForm', 'EndpointForm', 'EventSocketConfigForm',
    'SofiaGatewayForm', 'SipProfileForm')


stun_re = re.compile("^stun:\w+(?:[A-Z0-9-]+\.)+[A-Z]{2,6}$", re.IGNORECASE)

ADDRESS_CONSTANTS = ('auto', 'auto-nat')

class FreeswitchAddressField(forms.CharField):
    def __init__(self, max_length=100, initial='auto', *args, **kwargs):
        super(FreeswitchAddressField, self).__init__(
            max_length=max_length, initial=initial, *args, **kwargs)
        
    def clean(self, value):
        if (value in ADDRESS_CONSTANTS or validate_ipv4_address(value)
            or stun_re.match(value)):
            return value
        else:
            raise forms.ValidationError(
                "This field must be set to an IP address, STUN address "
                "(e.g. stun:stun.freeswitch.org) or \"auto\"/\"auto-nat\".")
        

class ConfigMailserverForm(forms.Form):
    from_email = forms.EmailField()
    email_host = forms.CharField(max_length=100)
    email_port = forms.IntegerField(min_value=1)
    auth_user = forms.CharField(
        max_length=100, required=False,
        help_text="Enable if your mail server requires login credentials")
    auth_password = forms.CharField(
        max_length=100, required=False,
        widget=widgets.PasswordInput(),
        help_text="Enable if your mail server requires login credentials")
    use_tls = forms.BooleanField(
        required=False,
        help_text=("Enable if your mail server requires Transport Layer "
                   "Security (TLS) encryption"))

    
class TestMailserverForm(forms.Form):
    recipient = forms.CharField(max_length=75)
    subject = forms.CharField(max_length=75)
    ta_msg_body = widgets.Textarea({'rows': '20', 'cols': '70'})    
    msg_body = forms.CharField(max_length=500, widget=ta_msg_body)    


class ExtensionForm(forms.Form):
    dest_num = forms.CharField(
        max_length=75, label="Extension #",
        help_text=("This is a regular expression like \"^100\d{5,8}$\". "
                   "Note: to enter the asterisk character you must use \* "
                   "since * has a special meaning for regexes."))
    desc = forms.CharField(max_length=250)
    ta_actions_xml = widgets.Textarea({'rows': '20', 'cols': '70'})
    actions_xml = forms.CharField(
        max_length=5000, required=True, widget=ta_actions_xml)

    def clean_dest_num(self):
        value = self.cleaned_data['dest_num']
        try:
            re.compile(value)
        except Exception:
            raise forms.ValidationError("Invalid regex")
        else:
            return value


class SoundclipForm(forms.Form):
    name = forms.CharField(max_length=100, label="Soundclip Name")
    desc = forms.CharField(max_length=100, label="Description")

    
class IvrForm(forms.Form):
    name = forms.CharField(max_length=100)
    language_ext = forms.CharField(
        max_length=100, label="Language Extension",
        help_text="(eg use py for python, lua for lua, etc)")
    ta_ivr_code = widgets.Textarea({'rows': '20', 'cols': '70'})
    ivr_code = forms.CharField(
        max_length=50000, required=True, widget=ta_ivr_code)


class UserProfileForm(forms.Form):
    email = forms.EmailField()
    password = forms.CharField(max_length=100, widget=widgets.PasswordInput())
    first_name=forms.CharField(max_length=100)
    last_name=forms.CharField(max_length=100)
    is_admin=forms.BooleanField(initial=False, required=False)
    is_active=forms.BooleanField(initial=True, required=False)


class UserProfileEditForm(forms.Form):
    email = forms.EmailField(max_length=100)
    first_name=forms.CharField(max_length=100)
    last_name=forms.CharField(max_length=100)
    is_active=forms.BooleanField(initial=True)


class RootUserForm(forms.Form):
    blurb = ("WikiPBX has a single root user which acts as the " 
             "superuser, operating outside of all accounts (tenants), "
             "and has unlimited security access.  Once these values "
             "have been entered they cannot be changed via the GUI, "
             "and the only way to modify them will be to go direct "
             "to the database.  Ditto goes for lost/forgotten root "
             "passwords.")
    email = forms.EmailField(max_length=100)
    password = forms.CharField(
        max_length=100, widget=widgets.PasswordInput())    
    first_name=forms.CharField(max_length=100)
    last_name=forms.CharField(max_length=100)
    is_active=forms.BooleanField(initial=True)
    is_superuser=forms.BooleanField(initial=True)    


class SipProfileForm(forms.Form):
    blurb = ("FreeSWITCH can listen on multiple ports (eg, 5060, 5061) "
             "and ip addresses.  Each one of these listening points requires "
             "its own sip profile.  Most installations can get by with a "
             "single profile that listens on port 5060 of the internet-facing "
             "ip address")
    name = forms.CharField(max_length=50, label="Sip Profile Name",
                           help_text="eg, external, internal, etc..")
    ext_rtp_ip = FreeswitchAddressField(
        label="External RTP IP",
        help_text=("External/public IP address to bind to for RTP."))
    ext_sip_ip = FreeswitchAddressField(
        label="External SIP IP",
        help_text=("External/public IP address to bind to for SIP."))
    rtp_ip = FreeswitchAddressField(
        label="RTP IP",
        help_text=("Internal IP address to bind to for RTP."))
    sip_ip = FreeswitchAddressField(
        label="SIP IP",
        help_text=("Internal IP address to bind to for SIP."))
    sip_port = forms.IntegerField(label="SIP port", min_value=1)
    accept_blind_reg = forms.BooleanField(
        initial=False, required=False, label="Accept Blind Registration",
        help_text=("If true, anyone can register to server and will "
                   "not be challenged for username/password information"))
    auth_calls = forms.BooleanField(
        initial=True, required=False, label="Auth Calls",
        help_text=("If true, FreeeSWITCH will authorize all calls, eg, "
                   "challenge the other side for username/password information"))

    
class AccountAndAdminForm(forms.Form):
    """
    Form that adds an account and and admin at the same time.
    """
    blurb = ("An account is essentially a Tenant.  WikiPBX is designed in "
             "such a way to minimize data sharing between accounts, so for "
             "example each account has its own set of users, endpoints, "
             "gateways, call detail records,  and dialplan that is not "
             "shared with other accounts.  When an account is created you "
             "must specify an initial  account admin, which can later be  "
             "modified or deleted.")
    name = forms.CharField(
        max_length=50, label="Account Name",
        help_text=("Name of account, eg, yourcompany or yourcompany.com"))
    enabled = forms.BooleanField(initial=True, required=False)
    domain = forms.CharField(
        max_length=100, label='Domain', required=False,
        help_text=("The domain associated with this account, eg. "
                   "sip.yourcompany.com. Endpoints belonging to this account "
                   "should be configured to register to this domain."))
    dialout_profile = forms.ChoiceField(
        label="Dialout SIP Profile ",
        help_text=("When web dialout is used for this account, "
                   "which SIP profile should it use?"))

    labeltxt = "Alias this domain to Dialout SIP profile?"
    help_text = ("When checked, this account's domain will become an " +
                 "alias for the dialout sip profile.")
    aliased = forms.BooleanField(initial=True, required=False,
                                 label=labeltxt,
                                 help_text=help_text)

    email = forms.EmailField(label="Admin Email")
    password = forms.CharField(
        max_length=100, label="Admin Password", widget=widgets.PasswordInput)
    first_name=forms.CharField(max_length=100, label="Admin First Name")
    last_name=forms.CharField(max_length=100, label="Admin Last Name")
    is_active=forms.BooleanField(initial=True)

    def __init__(self, sip_profiles, *args, **kwargs):

        # the current sip_profile is selected based on the
        # dialout_profile key in the form dictionary (see form_dict()
        # method in Account model)

        super(AccountAndAdminForm, self).__init__(*args, **kwargs)
        ddp_choices = []
        for sip_profile in sip_profiles:
            ddp_choices.append((sip_profile.id,
                                sip_profile.name))
        self.fields['dialout_profile'].choices = ddp_choices

class AccountForm(forms.Form):
    name = forms.CharField(
        max_length=50, label="Account Name",
        help_text=("Name of account, eg, yourcompany or yourcompany.com"))
    enabled = forms.BooleanField(initial=True, required=False)
    domain = forms.CharField(
        max_length=100, label='Domain', required=False,
        help_text=("The domain associated with this account, eg. "
                   "sip.yourcompany.com. Endpoints belonging to this account "
                   "should be configured to register to this domain."))
    dialout_profile = forms.ChoiceField(
        label="Dialout SIP Profile ",
        help_text=("When WikiPBX generates dial strings for this domain, "
                   "which SIP profile should it use?"))


    labeltxt = "Alias this domain to Dialout SIP profile?"
    help_text = ("When checked, this account's domain will become an " +
                 "alias for the dialout sip profile.")
    aliased = forms.BooleanField(initial=True, required=False,
                                 label=labeltxt,
                                 help_text=help_text)


    def __init__(self, sip_profiles, *args, **kwargs):

        # the current sip_profile is selected based on the
        # dialout_profile key in the form dictionary (see form_dict()
        # method in Account model)

        super(AccountForm, self).__init__(*args, **kwargs)
        ddp_choices = []
        for sip_profile in sip_profiles:
            ddp_choices.append((sip_profile.id,
                                sip_profile.name))
        self.fields['dialout_profile'].choices = ddp_choices
        
        
class EndpointForm(forms.Form):
    userid = forms.CharField(
        max_length=100, label="User ID",
        help_text=("The User ID the SIP endpoint logs in with. Normally "
                   "this should be numeric, for example: 101. This is only a "
                   "recommendation and not a hard rule, and this can be "
                   "anything, for example my_sip_endpoint_101@foo.com."))
    # tried to set widget=widgets.PasswordInput() for this field
    # but for some reason the field value keeps coming up blank
    # on the edit form
    password = forms.CharField(max_length=100, required=False)
    userprof = forms.ChoiceField(
        label="Web User",
        help_text=("(Optional) Associate this endpoint with an existing Web "
                   "User."))
    extension_num = forms.CharField(
        max_length=100, label="Extension #",
        help_text=("Every extension needs to have a unique string that "
                   "identifies it.  This can be a number, such as 101, or "
                   "a string, such as my_echotest.  If its a string it will "
                   "be impossible to directly dial on a standard telephone, "
                   "so a number is highly recommended."))
    extension_desc = forms.CharField(
        max_length=100, label="Description",
        help_text=("Enter a description that helps you identify this "
                   "extension.  For example, if this endpoint will be "
                   "provisioned for Bob in Accounting, this description "
                   "should say something to that effect"))
    extension_action = forms.ChoiceField(
        choices=[("bridge_vm", "Dial Endpoint + fallback to mod_voicemail"),
                 ("bridge", "Dial Endpoint")])
    
    def __init__(self, userprofs, show_none, *args, **kwargs):
        super(EndpointForm, self).__init__(*args, **kwargs)
        userprof_choices = []
        if show_none:
            userprof_choices.append((-1,"None"))                
        if userprofs:
            for userprof in userprofs:
                if not userprof:
                    continue
                if type(userprof) == type(""):
                    continue                
                userprof_choices.append((userprof.user.id,
                                         userprof.user.email))
        self.fields['userprof'].choices = userprof_choices


class EventSocketConfigForm(forms.Form):
    listen_ip = forms.CharField(max_length=15)
    listen_port = forms.IntegerField(min_value=1)
    password = forms.CharField(max_length=25)

    def clean_listen_ip(self):
        value = self.cleaned_data['listen_ip']
        if validate_ipv4_address(value):
            return value
        else:
            raise forms.ValidationError('Not a valid IPv4 field')        


class SofiaGatewayForm(forms.Form):
    name = forms.CharField(
        max_length=100, required=True, label="Gateway Name")
    sip_profile = forms.ChoiceField(
        label="Sip Profile",
        help_text=("Which Sip Profile communication with this gateway will "
                   "take place on"))
    username = forms.CharField(
        max_length=25, help_text="Username for gateway login/authentication")
    password = forms.CharField(
        max_length=25, help_text="Password for gateway login/authentication",
        widget=widgets.PasswordInput())
    proxy = forms.CharField(
        max_length=50,
        help_text="proxy host: *optional* same as realm, if blank")
    register = forms.BooleanField(
        initial=False, required=False, help_text="register w/ the gateway?")
    extension = forms.CharField(
        max_length=50, required=False,
        help_text=("extension for inbound calls: *optional* same as username,"
                   " if blank"))
    realm = forms.CharField(
        max_length=50, required=False,
        help_text="auth realm: *optional* same as gateway name, if blank")
    from_domain = forms.CharField(
        max_length=50, required=False,
        help_text="domain to use in from: *optional* same as realm, if blank")
    expire_seconds = forms.IntegerField(
        initial=60, help_text="expire in seconds: *optional* 3600, if blank")
    retry_seconds = forms.IntegerField(
        initial=30,
        help_text=("How many seconds before a retry when a failure or "
                   "timeout occurs"))
    caller_id_in_from = forms.BooleanField(
        initial=False, required=False,
        help_text=("Use the callerid of an inbound call in the from field on "
                   "outbound calls via this gateway"))
    accessible_all_accts = forms.BooleanField(
        initial=False, required=False,
        help_text=("Are other WikiPBX accounts allowed to dial out of this gateway?"))
    
    def __init__(self, sip_profiles, show_none, *args, **kwargs):
        super(SofiaGatewayForm, self).__init__(*args, **kwargs)

        # when showing an edit gateway form, the sip_profile is selected
        # based on the sip_profile key in the form dictionary (see form_dict()
        # method in SofiaGateway model)
        
        sip_profile_choices = []
        if show_none:
            sip_profile_choices.append((-1,"None"))                
        if sip_profiles:
            for sip_profile in sip_profiles:
                if not sip_profile:
                    continue
                if type(sip_profile) == type(""):
                    continue                
                sip_profile_choices.append((sip_profile.id,
                                         sip_profile.name))
        self.fields['sip_profile'].choices = sip_profile_choices
