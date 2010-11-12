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
import datetime
import itertools
import os
import re
from django import http
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.views.generic import simple
from wikipbx import logger, fsutil, utils, authutil, modelutils, extensionutil
from wikipbx import xmlconfig, cdrutil, mailutil, sofiautil, ttsutil, statics
from wikipbx import migrate
from wikipbx.wikipbxweb.models import *
from wikipbx.wikipbxweb.forms import *
from wikipbx.wikipbxweb.paginator import Paginator
from xml.dom import minidom


def index(request):
    return simple.direct_to_template(
        request, 'index.html', {'nousers': not User.objects.all()})

def dashboard(request):
    if not request.user.is_authenticated():
        msg = "Must be logged in to view this resource"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)    
    return simple.direct_to_template(request, 'dashboard.html')

def memberlogin(request):
    if request.GET or request.POST:
        # submitted form
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if not user:
            msg = ("Authentication failed.  Please try again, make sure the " 
                   "CAPS-LOCK key is off and there are no typo's.")
            return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
        else:
            login(request, user)
            return http.HttpResponseRedirect("/dashboard/")
    else:
        return http.HttpResponseRedirect("/")        

def memberlogout(request):
    if not request.user.is_authenticated():
        msg = "You are not currently logged in"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    
    logout(request)
    msg = "You have been logged out"
    return http.HttpResponseRedirect("/?infomsg=%s" % msg)

def extensions(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account
    if not request.POST:
        exts = Extension.objects.filter(account=account,
                                        is_temporary=False)
        exts = exts.order_by("priority_position")
        return simple.direct_to_template(
            request, 'extensions.html', {'exts': exts})

def ext_priority(request, extension_id, action):
    """
    @action 'highest', 'lowest', 'raise', 'lower'
    """
    account = request.user.get_profile().account
    extension = Extension.objects.get(pk=extension_id)
    msg = "Error"
    if action in ["lowest", "highest"]:
        extensionutil.reset_priority_position(account, extension, action)
        msg = "Extension priority set to %s" % action
    elif action in ["raise", "lower"]:
        extensionutil.bump_priority_position(account, extension, action)
        msg = "Extension priority %sed" % action
    return http.HttpResponseRedirect("/extensions/?infomsg=%s" % msg)
    
def edit_extension(request, extension_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)

    account = request.user.get_profile().account
    extension = Extension.objects.get(pk=extension_id)
    invalid = False
    if request.POST:
        # process form
        form = ExtensionForm(request.POST)        
        if form.is_valid():
            # valid, save info
            actions_xml = form.clean_data['actions_xml']
            # does xml parse?
            xml_str = "<fakeroot>%s</fakeroot>" % actions_xml
            minidom.parseString(str(xml_str))
            extension.dest_num = form.clean_data['dest_num']
            extension.desc = form.clean_data['desc']

            # ugh, its too time consuming to do the auth_call
            # radio buttons using the ExtensioForm, just use HTML/POST
            auth_call_str = request.POST['auth_call']
            if auth_call_str and auth_call_str.lower() == "true":
                auth_call = True
            else:
                auth_call = False
            extension.auth_call = auth_call
            
            extension.actions_xml = actions_xml
            extension.save()
            msg = "Extension %s saved" % extension
            return http.HttpResponseRedirect("/extensions/?infomsg=%s" % msg)
        else:
            invalid = True
    else:
        # show form
        form = ExtensionForm(extension.form_dict())
    return simple.direct_to_template(
        request, 'edit_extension.html',
        {'form': form, 'extension': extension, 'invalid': invalid,
         'templates': extensionutil.get_templates(account)})

def del_extension(request, extension_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account                
    extension = Extension.objects.get(account=account,
                                      pk=extension_id)
    extension.delete()
    msg = "Extension %s deleted" % extension
    return http.HttpResponseRedirect("/extensions/?infomsg=%s" % msg)
        
def add_extension(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        

    account = request.user.get_profile().account
    if request.POST:
        # process form
        dest_num = request.POST['dest_num']

        # make sure that dest_num is a valid regex
        # TODO: use ExtensionForm here for validation
        try:
            re.compile(dest_num)
        except Exception:
            msg = "Sorry, %s does not appear to be a valid regular expression" % dest_num
            return http.HttpResponseRedirect("/add_extension/?urgentmsg=%s" % msg)
        
        desc = request.POST['desc']
        if not dest_num or not desc:
            msg = "Sorry, form is missing required fields."
            return http.HttpResponseRedirect("/add_extension/?urgentmsg=%s" % msg)
        extension_type = request.POST['extension_type']
        associated_endpoint = None
        if extension_type == "raw_xml":
            actions_xml = request.POST['actions_xml']
            # does xml parse?
            minidom.parseString("<fakeroot>%s</fakeroot>" % actions_xml)
        elif extension_type == "local_endpoint":
            endpoint_id = request.POST['endpoint']
            endpoint = Endpoint.objects.get(pk=endpoint_id)
            extension_action = request.POST['extension_action']
            actions_xml = extensionutil.endpoint_wizard(endpoint,
                                                        extension_action)
            associated_endpoint = endpoint

        priority = extensionutil.new_ext_priority_position(account)
        auth_call_str = request.POST['auth_call']
        if auth_call_str and auth_call_str.lower() == "true":
            auth_call = True
        else:
            auth_call = False
        Extension.objects.create(
            account=account, dest_num=dest_num, auth_call=auth_call,
            priority_position=priority, actions_xml=actions_xml,
            desc=desc, endpoint=associated_endpoint)
        msg = "Extension was saved"
        return http.HttpResponseRedirect("/extensions/?infomsg=%s" % msg)

    form = ExtensionForm()
    return simple.direct_to_template(
        request, 'add_extension.html',
        {'form': form, 'endpoints': Endpoint.objects.filter(account=account),
         'templates': extensionutil.get_templates(account)})

def ivrs(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    if request.POST:
        raise Exception("POST request invalid here")
    account = request.user.get_profile().account    
    account_ivrs = Ivr.objects.filter(account=account)
    system_ivrs = Ivr.objects.filter(account__isnull=True)
    return simple.direct_to_template(
        request, 'ivrs.html',
        {'account_ivrs':account_ivrs, 'system_ivrs':system_ivrs})    
        
def edit_ivr(request, ivr_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    account = request.user.get_profile().account
    ivr = Ivr.objects.get(pk=ivr_id)
    if request.POST:
        # process form
        # if its a system ivr, only root can edit
        if not ivr.account:
            if not request.user.is_superuser:
                msg = "Only root can edit system-wide ivrs" % ivr
                return http.HttpResponseRedirect("/ivrs/?urgentmsg=%s" % msg)
        form = IvrForm(request.POST)        
        if form.is_valid():
            ivr.name = form.clean_data['name']
            ivr.language_ext = form.clean_data['language_ext']
            ivr.save()
            ivr.script2file(form.clean_data['ivr_code'])
            msg = "Ivr %s saved" % ivr
            return http.HttpResponseRedirect("/ivrs/?infomsg=%s" % msg)
    else:
        # show form
        form = IvrForm(ivr.form_dict())

    return simple.direct_to_template(
        request, 'edit_ivr.html',
        {'form':form, 'ivr':ivr, 'action_xml':ivr.get_action_xml()})

def del_ivr(request, ivr_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account                
    ivr = Ivr.objects.get(account=account, pk=ivr_id)
    ivr.delete()
    msg = "Ivr %s deleted" % ivr
    return http.HttpResponseRedirect("/ivrs/?infomsg=%s" % msg)

def del_account(request, account_id):
    if not authutil.is_root_or_admin(request, account_id):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = Account.objects.get(pk=account_id)
    account.delete()
    return fsutil.restart_profiles(
        "Account deleted. FreeSWITCH notified",
        "Account deleted, failed to notify FreeSWITCH: %s",
        '/accounts/')

def del_sip_profile(request, sip_profile_id):
    if not authutil.is_root(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    sip_profile = SipProfile.objects.get(pk=sip_profile_id)
    gateways = sip_profile.get_gateways()
    if gateways:
        msg = ("There are still %s gateways associated with this "
               "sip profile, fix this first." % len(gateways))
        return http.HttpResponseRedirect("/sip_profiles/?urgentmsg=%s" % msg)
    sip_profile.delete()
    return fsutil.restart_profiles(
        "Sip Profile deleted. FreeSWITCH notified",
        "Sip Profile deleted, failed to notify FreeSWITCH: %s",
        '/sip_profiles/')

def event_socket(request):
    if (not request.user.is_authenticated() or
        not request.user.is_superuser):        
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)

    eventsockets = EventSocketConfig.objects.all()
    if eventsockets:
        eventsocket = eventsockets[0]
    else:
        # create a blank one
        eventsocket = EventSocketConfig.objects.create(
            listen_ip="127.0.0.1", listen_port="8021", password="CHANGE_ME")
    
    if request.POST:
        # process form
        form = EventSocketConfigForm(request.POST)        
        if form.is_valid():
            eventsocket.listen_ip = form.clean_data['listen_ip']
            eventsocket.listen_port = form.clean_data['listen_port']
            eventsocket.password = form.clean_data['password']            
            eventsocket.save()
            msg = "EventSocketConfig config %s updated" % eventsocket.id
            return http.HttpResponseRedirect("/dashboard?infomsg=%s" % msg)
    else:
        form = EventSocketConfigForm(eventsocket.form_dict())                
        
    # show form
    return simple.direct_to_template(
        request, 'event_socket.html', {'form':form})
        
def add_ivr(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    account = request.user.get_profile().account
    if request.POST:
        # process form
        form = IvrForm(request.POST)        
        if form.is_valid():
            ivr = Ivr(
                name=form.clean_data['name'], account=account,
                language_ext=form.clean_data['language_ext'])
            ivr.save()
            ivr.script2file(form.clean_data['ivr_code'])
            msg = "Ivr %s saved" % ivr
            return http.HttpResponseRedirect("/ivrs/?infomsg=%s" % msg)

    # show form
    form = IvrForm()
    return simple.direct_to_template(
        request, 'object_form.html', {'form':form})

def edit_account(request, account_id):
    if not authutil.is_root_or_admin(request, account_id):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    account = Account.objects.get(pk=account_id)
    sip_profiles = SipProfile.objects.all()
    if request.POST:
        # process form
        form = AccountForm(sip_profiles, request.POST)        
        if form.is_valid():
            dp_id=form.clean_data['dialout_profile']
            dialout_profile = SipProfile.objects.get(pk=dp_id)

            account.name = form.clean_data['name']
            account.enabled = form.clean_data['enabled']
            account.domain = form.clean_data['domain']            
            account.enabled = form.clean_data['enabled']
            account.dialout_profile=dialout_profile
            account.aliased=form.clean_data['aliased']
            account.save()
            referer = utils.strip_url_params(request.META['HTTP_REFERER'])

            return fsutil.restart_profiles(
                "Account updated.  Attempted to restart sofia profile, but "
                "you may need to restart freeswitch if profile was never "
                "started (due to port conflict)",
                "Account updated, failed to restart Sofia: %s",
                referer)
    else:
        form = AccountForm(sip_profiles, account.form_dict())                
        
    # show form
    return simple.direct_to_template(
        request, 'object_form.html', {'form':form})    

def add_sip_profile(request):
    if (not request.user.is_authenticated() or
        not request.user.is_superuser):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    if request.POST:
        # process form
        form = SipProfileForm(request.POST)        
        if form.is_valid():
            sipprofile = SipProfile.objects.create(
                name=form.clean_data['name'],
                ext_rtp_ip=form.clean_data['ext_rtp_ip'],
                ext_sip_ip=form.clean_data['ext_sip_ip'],
                rtp_ip=form.clean_data['rtp_ip'],
                sip_ip=form.clean_data['sip_ip'],
                sip_port=form.clean_data['sip_port'],
                accept_blind_reg = form.clean_data['accept_blind_reg'],
                auth_calls = form.clean_data['auth_calls'])
            return fsutil.restart_profiles(
                "Sip Profile updated. FreeSWITCH notified",
                "Sip Profile updated, failed to notify FreeSWITCH: %s",
                '/sip_profiles/')
    else:
        # show form
        form = SipProfileForm()

    return simple.direct_to_template(
        request, 'object_form.html', {'form':form,
                                      'blurb':form.blurb})

def edit_sip_profile(request, profile_id):
    if (not request.user.is_authenticated() or
        not request.user.is_superuser):    
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    sipprofile = get_object_or_404(SipProfile, pk=profile_id)
    if request.POST:
        # process form
        form = SipProfileForm(request.POST)        
        if form.is_valid():
            sipprofile.name = form.clean_data['name']
            sipprofile.ext_rtp_ip = form.clean_data['ext_rtp_ip']
            sipprofile.ext_sip_ip = form.clean_data['ext_sip_ip']
            sipprofile.rtp_ip = form.clean_data['rtp_ip']
            sipprofile.sip_ip = form.clean_data['sip_ip']
            sipprofile.sip_port = form.clean_data['sip_port']
            sipprofile.accept_blind_reg = form.clean_data['accept_blind_reg']
            sipprofile.auth_calls = form.clean_data['auth_calls']
            sipprofile.save()
            return fsutil.restart_profiles(
                "Sip Profile updated. FreeSWITCH notified",
                "Sip Profile updated, failed to notify FreeSWITCH: %s",
                '/sip_profiles/')
    else:
        # show form
        form = SipProfileForm(sipprofile.form_dict())

    return simple.direct_to_template(
        request, 'object_form.html', {'form':form, 
                                      'blurb':form.blurb})

def add_account(request):
    if (not request.user.is_authenticated() or
        not request.user.is_superuser):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        

    sip_profiles = SipProfile.objects.all()
    if request.POST:
        # process form
        form = AccountAndAdminForm(sip_profiles, request.POST)        
        if form.is_valid():
            try:
                transaction.enter_transaction_management()
                transaction.managed(True)

                dp_id=form.clean_data['dialout_profile']
                dialout_profile = SipProfile.objects.get(pk=dp_id)
                
                account = Account.objects.create(
                    name=form.clean_data['name'],
                    enabled=form.clean_data['enabled'],
                    domain=form.clean_data['domain'],
                    dialout_profile=dialout_profile,
                    aliased=form.clean_data['aliased'])

                email = form.clean_data['email']
                password = form.clean_data['password']            
                user = User.objects.create_user(email, email, password)
                user.first_name = form.clean_data['first_name']
                user.last_name = form.clean_data['last_name']
                user.is_staff = False
                user.is_active = form.clean_data['is_active']
                user.is_superuser = False    
                user.save()

                userprof = UserProfile.objects.create(
                    user=user, account=account)

                account.admins.add(userprof)
                
                # commit transaction
                transaction.commit()
                transaction.leave_transaction_management()

                return fsutil.restart_profiles(
                    "Account added. FreeSWITCH notified",
                    "Account added, failed to notify FreeSWITCH: %s",
                    '/accounts/')
        
            except Exception, e:
                logger.error("Error adding account: %s" % str(e))
                try:
                    transaction.rollback()
                    msg = "Error adding account: %s" % str(e)
                except Exception, e2:
                    transaction.leave_transaction_management()            
                    logger.error(e2)
                    msg = "Error adding account"
                return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)
    else:
        if sip_profiles:
            form = AccountAndAdminForm(sip_profiles)
        else:
            # first make sure we have at least one sip profile defined
            msg = ("Sorry, you must have at least one sip profile to "
                   "add an account")
            return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)
            
    return simple.direct_to_template(
        request, 'object_form.html', {'form':form,
                                      'blurb':form.blurb})

def users(request, account_id):
    if not authutil.is_root_or_admin(request, account_id):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    if request.POST:
        raise Exception("POST request invalid here")
    account = Account.objects.get(pk=account_id)    
    userprofs = UserProfile.objects.filter(account=account)
    return simple.direct_to_template(
        request, 'users.html', {'userprofs':userprofs, 'account':account})

def add_user(request, account_id):
    if not authutil.is_root_or_admin(request, account_id):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = Account.objects.get(pk=account_id)        
    if request.POST:
        # process form
        form = UserProfileForm(request.POST)        
        if form.is_valid():
            email = form.clean_data['email']
            try:
                transaction.enter_transaction_management()
                transaction.managed(True)
            
                user = User.objects.create_user(
                    email, email, form.clean_data['password'])
                user.first_name = form.clean_data['first_name']
                user.last_name = form.clean_data['last_name']
                user.is_staff = False
                user.is_active = form.clean_data['is_active']
                user.is_superuser = False
                user.save()

                userprof = UserProfile.objects.create(
                    user=user, account=account)

                is_admin = form.clean_data['is_admin']
                if is_admin:
                    account.admins.add(userprof)
                    
                transaction.commit()
                transaction.leave_transaction_management()

            except Exception, e:
                try:
                    transaction.rollback()
                except Exception, e2:
                    logger.error(e2)
                transaction.leave_transaction_management()
                msg = "User was not added: %s" % e
                return http.HttpResponseRedirect("/add_user/%s/?urgentmsg=%s" %
                                                 (account.id, msg))

            msg = "User %s added" % user
            return http.HttpResponseRedirect(
                "/users/%s/?infomsg=%s" % (account.id, msg))
        else:
            msg = "Form had errors"
            return http.HttpResponseRedirect("/add_user/%s/?urgentmsg=%s" %
                                             (account.id, msg))
    else:
        # show form
        form = UserProfileForm()

    return simple.direct_to_template(
        request, 'object_form.html', {'form':form})

def del_user(request, account_id, user_id):
    if not authutil.is_root_or_admin(request, account_id):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = Account.objects.get(pk=account_id)
    userprof = UserProfile.objects.get(pk=user_id, account=account)
    userprof.delete()
    msg = "User %s deleted" % user_id
    return http.HttpResponseRedirect(
        "/users/%s/?infomsg=%s" % (account.id, msg))
    
def edit_user(request, account_id, user_id):
    if not authutil.is_root_or_admin(request, account_id):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = Account.objects.get(pk=account_id)
    userprof = UserProfile.objects.get(pk=user_id, account=account)
    if request.POST:
        # process form
        form = UserProfileEditForm(request.POST)        
        if form.is_valid():
            userprof.user.email = form.clean_data['email']
            userprof.user.first_name = form.clean_data['first_name']
            userprof.user.last_name = form.clean_data['last_name']
            userprof.user.is_active = form.clean_data['is_active']
            userprof.save()
            userprof.user.save()
            msg = "User %s updated" % userprof
            return http.HttpResponseRedirect(
                "/users/%s/?infomsg=%s" % (account.id, msg))
        else:
            msg = "Form had errors"
            return http.HttpResponseRedirect("/add_user/%s/?urgentmsg=%s" %
                                             (account.id, msg))
    else:
        # show form
        form = UserProfileEditForm(userprof.form_dict())

    return simple.direct_to_template(
        request, 'object_form.html',
        {'form':form, 'account':account, 'userprofile':userprof})

def sip_profiles(request):
    if (not request.user.is_authenticated() or
        not request.user.is_superuser):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    if request.POST:
        raise Exception("POST request invalid here")
    sip_profiles = SipProfile.objects.all()
    return simple.direct_to_template(
        request, 'sip_profiles.html', {'sip_profiles':sip_profiles})    

def accounts(request):
    if (not request.user.is_authenticated() or
        not request.user.is_superuser):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    if request.POST:
        raise Exception("POST request invalid here")
    accounts = Account.objects.all()
    return simple.direct_to_template(
        request, 'accounts.html', {'accounts':accounts})
    
def gateways(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):        
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    if request.POST:
        raise Exception("POST request invalid here")
    account = request.user.get_profile().account    
    gateways = SofiaGateway.objects.filter(account=account)
    return simple.direct_to_template(
        request, 'gateways.html', {'gateways':gateways})    

def edit_gateway(request, gateway_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        

    account = request.user.get_profile().account
    gw = SofiaGateway.objects.get(pk=gateway_id)
    if request.POST:
        # process form
        form = SofiaGatewayForm(SipProfile.objects.all(), False, request.POST)        
        if form.is_valid():

            sip_profile_id = form.clean_data['sip_profile']
            gw.sip_profile = SipProfile.objects.get(pk=sip_profile_id)
            
            ciif = form.clean_data['caller_id_in_from']
            gw.name = form.clean_data['name']
            gw.username = form.clean_data['username']
            gw.password = form.clean_data['password']
            gw.proxy = form.clean_data['proxy']
            gw.register = form.clean_data['register']
            gw.extension = form.clean_data['extension']
            gw.realm = form.clean_data['realm']
            gw.from_domain = form.clean_data['from_domain']
            gw.expire_seconds = form.clean_data['expire_seconds']
            gw.retry_seconds = form.clean_data['retry_seconds']
            val = form.clean_data['accessible_all_accts']
            gw.accessible_all_accts = val
            gw.caller_id_in_from = ciif
            gw.save()

            return fsutil.restart_profiles(
                "Gateway updated. FreeSWITCH notified",
                "Gateway updated, failed to notify FreeSWITCH: %s",
                '/gateways/')
    else:
        # show form
        form = SofiaGatewayForm(SipProfile.objects.all(), False, gw.form_dict())

    return simple.direct_to_template(
        request, 'object_form.html', {'form':form, 'gateway':gw})

def del_gateway(request, gateway_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account            
    gateway = SofiaGateway.objects.get(account=account,
                                       pk=gateway_id)
    gateway.delete()

    return fsutil.restart_profiles(
        "Gateway deleted.  Sofia Profile Restarted",
        "Gateway deleted, failed to restart Sofia Profile: %s ",
        '/gateways')

def add_gateway(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account
    invalid = False
    if request.POST:
        form = SofiaGatewayForm(SipProfile.objects.all(), False, request.POST)
        if form.is_valid():
            sip_profile_id = request.POST['sip_profile']                
            if sip_profile_id and sip_profile_id != "-1":
                sip_profile = SipProfile.objects.get(pk=sip_profile_id)
            else:
                raise Exception("Could not find Sip Profile: %s" % sip_profile_id)

            ciif = form.clean_data['caller_id_in_from']
            aac = form.clean_data['accessible_all_accts']
            gw = SofiaGateway.objects.create(
                account=account, name=form.clean_data['name'],
                username=form.clean_data['username'],
                sip_profile=sip_profile,
                password=form.clean_data['password'],
                proxy=form.clean_data['proxy'],
                register=form.clean_data['register'],
                caller_id_in_from=ciif,
                extension=form.clean_data['extension'],
                realm=form.clean_data['realm'],
                from_domain=form.clean_data['from_domain'],
                expire_seconds=form.clean_data['expire_seconds'],
                retry_seconds=form.clean_data['retry_seconds'],
                accessible_all_accts = aac)

            return fsutil.restart_profiles(
                "Gateway added.  FreeSWITCH notified",
                "Gateway added, failed to notify FreeSWITCH: %s",
                '/gateways/')
        else:
            invalid = True            
    else:
        # not posting, show blank form
        form = SofiaGatewayForm(SipProfile.objects.all(), False)

    return simple.direct_to_template(
        request, 'add_gateway.html',
        {'form': form, 'invalid': invalid})

def add_endpoint(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    account = request.user.get_profile().account
    if request.POST:
        # process form
        userprof = request.POST['userprof']                
        if userprof and userprof != "-1":
            userprofile = UserProfile.objects.get(pk=userprof)
        else:
            userprofile = None

        userid = request.POST['userid']
        password = request.POST['password']
        if not userid or not password:
            msg = "Missing one or more required fields"
            return http.HttpResponseRedirect("/add_endpoint/?urgentmsg=%s" % msg)
        if request.POST.has_key('create_extension'):
            extension_num = request.POST['extension_num']
            extension_desc = request.POST['extension_desc']
            if not extension_num or not extension_desc:
                msg = "Missing one or more required fields"
                return http.HttpResponseRedirect(
                    "/add_endpoint/?urgentmsg=%s" % msg)
            
        try:
            transaction.enter_transaction_management()
            transaction.managed(True)
            endpoint = Endpoint(
                userid=userid, password=password, account=account,
                userprofile=userprofile, contact_addr="0.0.0.0")
            endpoint.save()

            if request.POST.has_key('create_extension'):
                extension_action = request.POST['extension_action']
                modelutils.post_create_endpoint(
                    endpoint, extension_num, extension_desc, extension_action)

            transaction.commit()
            transaction.leave_transaction_management()

        except Exception, e:
            logger.error(str(e))
            try:
                transaction.rollback()
            except Exception, e2:
                logger.error(str(e2))
            transaction.leave_transaction_management()
            msg = "Error creating endpoint %s " % e
            return http.HttpResponseRedirect("/endpoints/?urgentmsg=%s" % msg)
            
        msg = "Endpoint %s saved" % endpoint
        return http.HttpResponseRedirect("/endpoints/?infomsg=%s" % msg)

    else:
        # show form
        userprofs = UserProfile.objects.filter(account=account)
        form = EndpointForm(userprofs, True)

    return simple.direct_to_template(
        request, 'add_endpoint.html', {'form':form})

def endpoints(request):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):        
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        
    if request.POST:
        raise Exception("POST request invalid here")

    account = request.user.get_profile().account    
    endpoints = Endpoint.objects.filter(account=account)

    # which endpoints for this domain are reg'd?  ask freeswitch
    errorconnecting2fs = False
    for connection in fsutil.get_fs_connections():
        try:
            for endpoint in endpoints:
                # we have to check each profile, since in theory
                # and endpoint can be regd to any defined profile
                regd_on_any_profile = False
                for sipprofile in SipProfile.objects.all():
                    cmd = ("api sofia status profile %s user %s@%s" %
                           (sipprofile.name, endpoint.userid, account.domain))
                    results = connection.sendRecv(cmd)
                    if not results:
                        raise Exception("Could not connect to FreeSWITCH")
                    data = results.getBody().splitlines()
                    for line in data:
                        if line.startswith("Contact:"):
                            # found "Contact:", that means this endpoint is reg'd
                            endpoint.is_registered = True
                            break

        except Exception, e:
            errorconnecting2fs = True
            logger.error("Failed to update endpoints' registration status")
            logger.error("Detailed error: %s" % str(e))

    extra_context = {'endpoints':endpoints}
    if errorconnecting2fs:
        extra_context['urgentmsg'] = (
            "Failed to get current registration status from FreeSWITCH")
    return simple.direct_to_template(
        request, 'endpoints.html', extra_context)

def exts4endpoint(request, endpoint_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account
    endpoint = Endpoint.objects.get(pk=endpoint_id)
    exts = endpoint.extension_set.all()
    exts = exts.order_by("priority_position")
    return simple.direct_to_template(
        request, 'extensions.html', {'exts':exts, 'endpoint':endpoint})

def edit_endpoint(request, endpoint_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    
    account = request.user.get_profile().account
    endpoint = Endpoint.objects.get(pk=endpoint_id)
    if request.POST:
        # process form
        userprof = request.POST['userprof']                
        if userprof and userprof != "-1":
            userprofile = UserProfile.objects.get(pk=userprof)
        else:
            userprofile = None
        logger.debug("userprofile: %s" % userprofile)

        userid = request.POST['userid']
        password = request.POST['password']

        if not userid:
            msg = "Missing one or more required fields"
            return http.HttpResponseRedirect(
                "/edit_endpoint/%s/?urgentmsg=%s" %  (endpoint.id, msg))
        endpoint.userid = userid
        endpoint.password = password
        endpoint.userprofile = userprofile
        endpoint.save()
        msg = "Endpoint %s saved" % endpoint
        return http.HttpResponseRedirect("/endpoints/?infomsg=%s" % msg)

    else:
        # show form
        form = EndpointForm([], False, endpoint.form_dict())

    return simple.direct_to_template(
        request, 'edit_endpoint.html',
        {'form': form, 'endpoint': endpoint,
         'userprofs': UserProfile.objects.filter(account=account)})

def del_endpoint(request, endpoint_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account            
    endpoint = Endpoint.objects.get(account=account,
                                    pk=endpoint_id)
    modelutils.pre_delete_endpoint(endpoint)
    endpoint.delete()
    msg = "Endpoint %s deleted" % endpoint
    return http.HttpResponseRedirect("/endpoints/?infomsg=%s" % msg)

def del_soundclip(request, soundclip_id):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account        
    soundclip = Soundclip.objects.get(account=account,
                                      pk=soundclip_id)
    soundclip.delete()
    msg = "Soundclip %s deleted" % soundclip
    return http.HttpResponseRedirect("/soundclips/?infomsg=%s" % msg)

def add_soundclip(request):
    if (not request.user.is_authenticated()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)

    account = request.user.get_profile().account    
    if request.POST:
        # TODO: make a temporary extension with dest num: add_clip_8787
        # and store in the database
        name = request.POST['name']
        if not name:
            raise Exception("You must enter a name for the soundclip")
        if Soundclip.objects.filter(account=account,
                                    name=name):
            raise Exception("Already a sound clip with that name")

        desc = request.POST['desc']
        upload_method = request.POST['upload_method']
        if upload_method == "dialout":
            vardict = {'name':name,
                       'desc':desc,
                       'account_id':account.id
                       }
            ivr_app = "wikipbx.ivr.soundclip_recorder" 
            action = '<action application="python" data="%s"/>' % ivr_app
            sound_clip_ext = extensionutil.get_temp_ext(vardict=vardict,
                                                        action=action,
                                                        tempname="soundclip",
                                                        account=account)
            dest_ext_app = sound_clip_ext

            # will go to dialout form where they can choose who
            # gets called
            return http.HttpResponseRedirect("/dialout/%s/" % dest_ext_app)
        elif upload_method == "wav":
            # NOTE: the following approach is very inefficient,
            # and causes the whole file to be loaded into memory.
            # There are better ways to do this..
            soundclip = Soundclip.objects.create(account=account,
                                                 name=name,
                                                 desc=desc)            
            upload_wav_dict = request.FILES['upload_wav']
            content_type = upload_wav_dict['content-type']
            content = upload_wav_dict['content']
            open(soundclip.get_path(), 'w').write(content)
            msg = "Soundclip was uploaded"
            return http.HttpResponseRedirect("/soundclips/?msg=%s" % msg)
        elif upload_method == "wav_url":
            try:
                utils.download_url(
                    request.POST['wav_url'], soundclip.get_path())
            except Exception, e:
                msg = "Soundclip could not be uploaded: %s" % str(e)
                return http.HttpResponseRedirect(
                    "/soundclips/?urgentmsg=%s" % msg)
            else:
                soundclip = Soundclip.objects.create(
                    account=account, name=name, desc=desc)
                msg = "Soundclip was uploaded"
                return http.HttpResponseRedirect(
                    "/soundclips/?infomsg=%s" % msg)
        else:
            raise Exception("Unknown upload method: %s" % upload_method)

    else:
        form = SoundclipForm()

    return simple.direct_to_template(
        request, 'add_soundclip.html',
        {'form': form, 'endpoints': Endpoint.objects.filter(account=account)})

def soundclips(request):
    if (not request.user.is_authenticated()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    if request.POST:
        raise Exception("POST request invalid here")
    account = request.user.get_profile().account        
    soundclips = Soundclip.objects.filter(account=account)
    return simple.direct_to_template(
        request, 'soundclips.html',
        {'soundclips':soundclips, 'account':account})

def completedcalls(request, page=1):
    if (not request.user.is_authenticated() or
        not request.user.get_profile().is_acct_admin()):        
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    if request.POST:
        raise Exception("POST request invalid here")
    account = request.user.get_profile().account        
    completedcalls = CompletedCall.objects.filter(
        account=account).order_by("-hangup_time")
    paginator = Paginator(request, completedcalls, page, 15)
    return simple.direct_to_template(
        request, 'completedcalls.html',
        {'completedcalls':paginator.get_page(), 'paginator': paginator})

def outgoing2endpoint(request, endpoint_id):
    """
    Dialout to endpoint.
    """
    if (not request.user.is_authenticated()):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    endpoint = Endpoint.objects.get(pk=endpoint_id)
    
    connection = fsutil.get_fs_connection()
    try:
        # {ignore_early_media=true} is absolutely essential so that
        # ext2dialfrom does not consider the channel answered until the
        # other side picks up, and it ignores "pre-answers".  this ensure
        # playback does not start until other side picks up
        modifiers = {"ignore_early_media":"true"}
        
        # generate the call url.. this is a direct url to the
        # locally registered sip endpoint.  no extension mapping needed.
        # sofia/example/300@pbx.internal
        # sofia/<profile>/userid%domain
        party2dial = "%s%%%s" % (endpoint.userid,
                                 endpoint.account.get_domain())
        sofia_url = sofiautil.sip_dialout_url(party2dial,
                                              endpoint.account,
                                              modifiers)

        file2play = os.path.join(settings.INSTALL_ROOT,
                                 "soundclips",
                                 "welcome_echo.wav")

        action = (
            '<action application="answer"/>'
            '<action application="playback" data="%s"/>'
            '<action application="echo" />'
            ) % file2play
        sound_clip_ext = extensionutil.get_temp_ext(
            vardict={}, action=action, tempname="outgoing2endpoint",
            account=endpoint.account)
        connection.sendRecv(
            "bgapi originate %s %s" % (sofia_url, sound_clip_ext))
    
    except Exception, e:
        msg = "Dialout failed: %s " % str(e)
        if settings.DEBUG:
            raise
    else:
        msg = "Dialout succeeded"
    return http.HttpResponseRedirect("/endpoints/?infomsg=%s" % msg)

def add_root(request):
    if User.objects.filter(is_superuser=True):
        msg = "Already have root user"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)        

    if request.POST:
        # process form
        form = RootUserForm(request.POST)        
        if form.is_valid():

            email = form.clean_data['email']
            password = form.clean_data['password']            
            user = User.objects.create_user(email, email, password)
            user.first_name = form.clean_data['first_name']
            user.last_name = form.clean_data['last_name']
            user.is_staff = False
            user.is_active = form.clean_data['is_active']
            user.is_superuser = form.clean_data['is_superuser']
            user.save()

            msg = "Root %s added" % user
            return http.HttpResponseRedirect("/?infomsg=%s" % msg)
    else:
        # show form
        form = RootUserForm()

    return simple.direct_to_template(
        request, 'object_form.html', {'form':form, 
                                      'blurb':form.blurb})

def livecalls(request):
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account

    channels = []
    for connection in fsutil.get_fs_connections():
        try:
            results = connection.sendRecv("api show channels")
            if not results:
                raise Exception("Could not connect to FreeSWITCH")
            data = results.getBody().splitlines()

            if len(data) > 3:
                headers = data[0].split(',')
                header_strings = (
                    'name', 'dest', 'cid_num', 'cid_name', 'created', 'uuid')
                indexes = map(headers.index, header_strings)
                assert all(x != -1 for x in indexes), \
                       "Unable to parse Freeswitch response"
                for i in range(1, len(data) - 2):
                    values = data[i].split(',')
                    channels.append(dict(
                        (header_strings[j], values[indexes[j]])
                        for j in range(len(header_strings))))

        except Exception, e:
            msg = "Could not get live calls: %s" % str(e)
            url = "/dashboard/?urgentmsg=%s" % msg
            return http.HttpResponseRedirect(url)

        else:
            return simple.direct_to_template(
                request, 'livecalls.html', {'channels':channels})

def transfer(request, chan_uuid):
    """
    Transfer one or both legs of a call do a different extension.
    """
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account

    if not request.POST:
        # show form that asks them to pick extension
        exts = [
            x for x in Extension.objects.filter(
                account=account, is_temporary=False
                ).order_by("priority_position")
            if x.get_single_expansion()]
        return simple.direct_to_template(
            request, 'transfer.html',
            {'chan_uuid': chan_uuid, 'extensions': exts})
    else:
        try:
            # figure out where they want to transfer to  ..
            checked_dp_exts = request.POST.getlist(
                'checked_dialplan_extensions')
            dest_ext_id = checked_dp_exts[0] 
            ext = Extension.objects.get(account=account, pk=dest_ext_id)
            connection = fsutil.get_fs_connection()
            connection.sendRecv(
                "bgapi uuid_transfer %s %s" % (chan_uuid,
                                               ext.get_single_expansion()))
        except Exception, e:
            msg = "Transfer failed: %s" % str(e)
            return http.HttpResponseRedirect("/livecalls/?urgentmsg=%s" % msg)
        else:
            msg = "Call transferred"
            return http.HttpResponseRedirect("/livecalls/?infomsg=%s" % msg)

def broadcast2channel(request, chan_uuid):
    """
    broadcast a soundclip to both legs of channel
    """
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account

    if not request.REQUEST.has_key('action'):
        # show form that asks them to pick soundclip
        soundclips = Soundclip.objects.filter(account=account)
        return simple.direct_to_template(
            request, 'broadcast2channel.html',
            {'soundclips': soundclips, 'account': account,
             'chan_uuid': chan_uuid})
    else:
        try:
            # play the soundclip into the channel

            if request.REQUEST['action'] == "soundclip":
                soundclip_id = request.REQUEST['soundclip_id']
                soundclip = Soundclip.objects.get(pk=soundclip_id)
                file2play = soundclip.get_path()
            elif request.REQUEST['action'] == "tts":
                file2play = ttsutil.make_tts_file(
                    request.REQUEST['text2speak'], tts_voice=None,
                    cache=False)
            else:
                raise Exception(
                    "Unknown action: %s" % request.REQUEST['action'])

            connection = fsutil.get_fs_connection()
            connection.sendRecv(
                "bgapi uuid_broadcast %s '%s'" % (chan_uuid, file2play))
        except Exception, e:
            msg = "Broadcast failed: %s" % str(e)
            return http.HttpResponseRedirect(
                "/broadcast2channel/%s/?urgentmsg=%s" % (chan_uuid, msg))
            
        else:
            msg = "Broadcast succeeded"
            return http.HttpResponseRedirect(
                "/broadcast2channel/%s/?infomsg=%s" % (chan_uuid, msg))
    
def hangup_channels(request, chan_uuid=None):
    """
    If chan_id is not given, hangup all.
    """
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account

    try:
        connection = fsutil.get_fs_connection()
        connection.sendRecv(
            ("bgapi uuid_kill %s" % chan_uuid) if chan_uuid else "bgapi hupall")
    except Exception, e:
        msg = "Could not hangup call%s: %s" % (
            "" if chan_uuid else "s", str(e))
        url = "/livecalls/?urgentmsg=%s" % msg
    else:
        msg = "Call%s hangup succeeded" % ("" if chan_uuid else "s")
        logger.error(msg)
        url = "/livecalls/?infomsg=%s" % msg
    return http.HttpResponseRedirect(url)

def server_logs(request, page=1):
    if not request.user.is_superuser:
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)

    serverlogs = ServerLog.objects.all().order_by("-logtime")
    paginator = Paginator(request, serverlogs, page, 15)
    
    return simple.direct_to_template(
        request, 'server_logs.html',
        {'serverlogs':paginator.get_page(), 'paginator': paginator})

def migrate_import(request):
    if not request.user.is_superuser:
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)

    if not request.POST:
        # show form
        if not SipProfile.objects.all():
            msg = ("You do not have any sip profiles defined.  Please "
                   "define a sip profile and try again")
            raise Exception(msg)
        return simple.direct_to_template(
            request, 'migrate_import.html',
            {'sipprofiles':SipProfile.objects.all()})

    else:
        # process form and do import
        path2xml = request.REQUEST['path2xml']
        sipprofilename2use = request.REQUEST['sipprofilename2use']
        migrate.data_import_from_version_pt_5(path2xml, sipprofilename2use)
        msg = ("Migrate completed successfully, you should see new objects "
               "in the web gui now.")
        return http.HttpResponseRedirect("/dashboard/?infomsg=%s" % msg)
    

def config_mailserver(request):
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)
    account = request.user.get_profile().account
    emailconfigs = EmailConfig.objects.filter(account=account)
    invalid = False
    if request.POST:
        # collect form data and show form
        form = ConfigMailserverForm(request.POST)
        if form.is_valid():
            # create or update
            from_email = form.clean_data["from_email"]
            email_host = form.clean_data["email_host"]
            email_port = form.clean_data["email_port"]
            auth_user = form.clean_data["auth_user"]
            auth_password = form.clean_data["auth_password"]
            use_tls = form.clean_data["use_tls"]
            if emailconfigs:
                # update
                emailconfig = emailconfigs[0]
                emailconfig.from_email = from_email
                emailconfig.email_host = email_host
                emailconfig.email_port = email_port
                emailconfig.auth_user = auth_user
                emailconfig.auth_password = auth_password
                emailconfig.use_tls = use_tls
                emailconfig.save()
            else:
                # create
                emailconfig = EmailConfig.objects.create(
                    server=account.server, account=account,
                    from_email=from_email, email_host=email_host,
                    email_port=email_port, auth_user=auth_user,
                    auth_password=auth_password, use_tls=use_tls)

            msg = "Email server configuration successful"
            return http.HttpResponseRedirect("/dashboard/?infomsg=%s" % msg)
        else:
            invalid = True                
    else:
        if emailconfigs:
            emailconfig = emailconfigs[0]
            form = ConfigMailserverForm(emailconfig.form_dict())
        else:
            form = ConfigMailserverForm()

    return simple.direct_to_template(
        request, 'config_mailserver.html', {'invalid': invalid, 'form': form})

def test_mailserver(request):
    """
    Allow user to show test email from a web page to see if mailserver
    is correctly configured.
    """
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)

    account = request.user.get_profile().account
    emailconfigs = EmailConfig.objects.filter(account=account)
    if not emailconfigs:
        msg = "Sorry, no email servers configured for this account"
        return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)
    emailconfig = emailconfigs[0]
    invalid = False
    if request.POST:
        # collect form data and show form
        form = TestMailserverForm(request.POST)
        if form.is_valid():
            mailutil.acct_send(
                recipients=[form.clean_data["recipient"]],
                subject=form.clean_data["subject"],
                msg_body=form.clean_data["msg_body"], account=account)

            msg = "Test email was sent"
            return http.HttpResponseRedirect("/dashboard/?infomsg=%s" % msg)
        else:
            invalid = True

    else:
        form = TestMailserverForm()

    return simple.direct_to_template(
        request, 'test_mailserver.html', {'invalid': invalid, 'form': form})

def dialout(request, dest_ext_app):
    if not authutil.is_root_or_admin(request):
        msg = "You are not currently logged in w/ enough permissions"
        return http.HttpResponseRedirect("/dashboard/?urgentmsg=%s" % msg)

    account = request.user.get_profile().account

    if request.POST:
        # did user specify anything?
        something2dial = False
        
        logger.debug(
            "checked_dialplan_extensions: %s" % 
            request.POST.getlist('checked_dialplan_extensions'))

        checked_dp_exts = request.POST.getlist('checked_dialplan_extensions')
        if checked_dp_exts:
            something2dial = True
        
        dlist = []
        # dial the extensions that were checked (checkboxes)
        for checked_dp_ext in checked_dp_exts:
            # get the dialable url for this extension, eg,
            # sofia/mydomain.com/600@ip:port
            extension = Extension.objects.get(account=account,
                                              pk=checked_dp_ext)
            party2dial = extension.get_sofia_url()

            concurrent_fname = "concurrent_dpext_%s" % extension.id
            concurrent = int(request.POST[concurrent_fname])
            for i in xrange(0, concurrent):
                dlist.append((party2dial, dest_ext_app))

        # dial the additional extensions and sip urls
        # these are the ones in the free textfield(s)
        for i in xrange(1, 1000):
            num2check = "number_%s" % i
            if request.POST.has_key(num2check):
                something2dial = True
                number2dial = request.POST[num2check]
                if not number2dial:
                    continue
                # is it a sip url or an extension?
                if number2dial.find("@") != -1:
                    # sip url ..
                    party2dial = sofiautil.sip_dialout_url(
                        number2dial, account)
                else:
                    # extension
                    party2dial = sofiautil.extension_url(number2dial, account)

                # dial concurrent?
                concurrent_fname = "concurrent_number_%s" % i
                concurrent = int(request.POST[concurrent_fname])
                for i in xrange(0, concurrent):
                    dlist.append((party2dial, dest_ext_app))
            else:
                break

        if not something2dial:
            msg = "Nothing to dial. Ignored request."
            referer = utils.strip_url_params(
                request.META.get('HTTP_REFERER', "./"))
            url = "%s?urgentmsg=%s" % (referer, msg)
        else:
            try:
                connections = itertools.cycle(fsutil.get_fs_connections())
                for connection, params in itertools.izip(connections, dlist):
                    connection.sendRecv("bgapi originate %s %s" % params)
            except Exception, e:
                msg = "Dialout failed: %s " % str(e)
                url = "/dashboard/?urgentmsg=%s" % msg
            else:
                msg = "Dialout succeeded"
                url = "/dialout/%s/?infomsg=%s" % (dest_ext_app, msg)
        return http.HttpResponseRedirect(url)

    # find all endpoints for this account
    endpoints = Endpoint.objects.filter(account=account)
    
    # find all single-expansion extensions for this account
    extensions = [
        x for x in Extension.objects.filter(
            account=account, is_temporary=False).order_by("priority_position")
        if x.get_single_expansion()]

    return simple.direct_to_template(
        request, 'dialout.html',
        {'endpoints': endpoints, 'extensions': extensions,
         'dest_ext_app': dest_ext_app})

def add_cdr(request):
    """
    this is called by the freeswitch xml_cdr_curl module
    for an example xml file, see
    http://wiki.freeswitch.org/wiki/Mod_xml_cdr
    """
    try:
        if not request.POST:
            raise Exception("Not a POST request")
        if not request.POST.has_key('cdr'):
            raise Exception("Parameter 'cdr' not found")
        cdr = request.POST['cdr']
        cp = cdrutil.process(cdr)
        if cp:
            logger.debug("CDR Added")
        else:
            logger.debug("Ingoring CDR")
    except Exception, e:
        msg = "Fatal error adding cdr xml: %s" % e
        logger.error(str(e))
        try:
            now = datetime.datetime.now()
            ServerLog.objects.create(logtime=now, message=msg)
        except Exception, e:
            logger.error("Error adding server log entry: %s" % str(e))
        raise e
    return http.HttpResponse("OK")
    
def xml_dialplan(request):
    """
    This is called by freeswitch to get either configuration,
    dialplan, or directory settings.
    See
    http://wiki.freeswitch.org/wiki/Mod_xml_curl
    
    configuration example
    =====================

    {'key_value': ['conference.conf'], 'key_name': ['name'],
    'section': ['configuration'], 'tag_name': ['configuration'],
    'profile_name': ['default'], 'conf_name': ['250']}>

    """

    retval_template = (
        '<?xml version="1.0"?>\n<document type="freeswitch/xml">\n'
        '<section name="configuration" description'
        '="Various Configuration">\n%s\n</section>\n</document>')
    try:
        # security: only serve config to localhost for now
        # and try to add suppport for user/password authentication
        # that freeswitch already supports.  this should be stored
        # in the settings.py config, along with some other config
        # that is currently stored in the database.. like the 
        # listening port, but which makes more sense to store
        # in a file.
        if not request.POST:
            # fs should always send a POST, so its probably a browser
            # show test page
            if not request.user.is_superuser:
                msg = "You must be logged in as superuser"
                return http.HttpResponseRedirect("/?infomsg=%s" % msg)
            return simple.direct_to_template(
                request, 'xml_dialplan.html')

        if request.POST['section'] == "configuration":
            # when freeswitch contacts wikipbx to pull its
            # configuration, it should pass its event socket
            # port so wikipbx knows how to "call it back".
            # maybe it already does!  but for now, let the
            # user define freeswitch instances in the gui.
            # in any operation that involves connecting to
            # freeswitch, a freeswitch instances will need
            # to be explicitly chosen.   or better yet, a global
            # binding that can be easily changed from web gui.  
            logger.debug("got post: %s" % request.POST)

            # does it need to be wrapped in the retval_template?
            needsRetValTemplate = True

            # does it need <?xml version="1.0"?> header stripped off?
            needsXmlHeaderStripped = True

            if request.POST['key_value'] == "event_socket.conf":
                needsRetValTemplate = False
                needsXmlHeaderStripped = False
                raw_xml = xmlconfig.event_socket_config()
                logger.info("raw_xml: %s" % raw_xml)
            elif request.POST['key_value'] == "sofia.conf":
                needsRetValTemplate = False
                needsXmlHeaderStripped = False
                raw_xml = xmlconfig.sofia_config()
                logger.info("raw_xml: %s" % raw_xml)
            elif request.POST['key_value'] == "xml_cdr.conf":
                needsRetValTemplate = False
                needsXmlHeaderStripped = False
                raw_xml = xmlconfig.xml_cdr_config()
                logger.info("raw_xml: %s" % raw_xml)
            else:
                return http.HttpResponse(statics.not_found)                

            # strip xml header if needed
            xml_snippet = str(
                utils.xml_snippet_no_header(raw_xml) if needsXmlHeaderStripped
                else raw_xml)

            # wrap in retval_template if needed
            retval = (
                (retval_template % xml_snippet) if needsRetValTemplate
                else xml_snippet)
            
            return http.HttpResponse(retval, mimetype="text/plain")
        elif request.POST['section'] == "dialplan":
            logger.debug("Dialplan request: %s" % request.POST)
            try:
                raw_xml = xmlconfig.dialplan_entry(request)
                logger.info("raw_xml: %s" % raw_xml)
                return http.HttpResponse(raw_xml, mimetype="text/plain")
                
            except Exception, e:
                logger.error("Error generating dialplan: %s" % e)
                return http.HttpResponse(statics.not_found)
        elif request.POST['section'] == "directory":
            logger.debug("Directory request: %s" % request.POST)
            try:
                raw_xml = xmlconfig.directory(request)
                if raw_xml:
                    logger.info("raw_xml: %s" % raw_xml)
                    return http.HttpResponse(raw_xml, mimetype="text/plain")
                else:
                    logger.error("Returing not found response")
                    return http.HttpResponse(statics.not_found)
            except Exception, e:
                logger.error("Error generating directory: %s" % e)
                return http.HttpResponse(statics.not_found)
    except Exception, e:
        logger.error("Error generating config: %s" % e)
        return http.HttpResponse(statics.not_found)

