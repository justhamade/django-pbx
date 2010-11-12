#!/usr/bin/env python

import os
os.environ['DJANGO_SETTINGS_MODULE']='wikipbx.settings'

from django import db
from django.db import transaction
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User, Permission
from django.utils import simplejson

from pytz import timezone
import datetime
from xml.dom import minidom
from xml.dom.ext import PrettyPrint
import StringIO

from wikipbx.wikipbxweb.models import *
from wikipbx.wikipbxweb.forms import *
from wikipbx import logger

"""
Import script to import from an XML generated from wikipbx version 0.5.
Everything done in a transaction, so if any exceptions happen during
the import, the db will not be changed at all.
"""

# if true, doesn't actually write anything to db.  good for "dry runs"
DRY_RUN = False

def data_import_from_version_pt_5(path2xml, sipprofilename2use=None):
    """
    Main entry point ..
    """

    # are there any sip profiles defined?
    sipprofiles = SipProfile.objects.all()
    if not sipprofiles:
        raise Exception("No sip profiles defined.  Please define one "
                        "and try again")

    # are there multiple sip profiles defined but no sipprofile2use?
    if len(sipprofiles) > 1 and not sipprofile2use:
        raise Exception("Multiple sip profiles and sipprofile2use not "
                        "passed in")

    if len(sipprofiles) == 1:
        sipprofile = sipprofiles[0]
        logger.debug("Will use sip profile: %s" % sipprofile)
    else:
        # lookup actual profile with given name
        sipprofile = SipProfile.objects.get(name=sipprofilename2use)
        if not sipprofile:
            raise Exception("Could not find sip profile with name: %s" %
                            sipprofile2use)

    # does file exist?
    if not os.path.exists(path2xml):
        raise Exception("Did not find file: %s. Did you upload to server?" %
                        path2xml)

    # parse in the contents in path2xml into a dom object
    dom = minidom.parse(path2xml)

    # get root elt
    root_elt = get_root(dom)
    logger.debug("elt: %s" % root_elt.localName)

    try:
        transaction.enter_transaction_management()
        transaction.managed(True)

        create_accounts(root_elt, sipprofile)

        create_userprofiles(dom, sipprofile)

        create_endpoints(dom, sipprofile)

        create_extensions(dom, sipprofile)

        create_gateways(dom, sipprofile)

        if DRY_RUN:
            raise Exception("Dry Run")
    
        transaction.commit()
        transaction.leave_transaction_management()

    except Exception, e:
        try:
            logger.debug("!!CRITICAL ERROR!! ROLLING BACK ALL CHANGES")
            logger.debug("Exception: %s" % e)
            transaction.rollback()
            logger.debug("Transaction rollback completed successfully")
        except Exception, e2:
            logger.debug("Exception trying to rollback!!")
            transaction.leave_transaction_management()
            

def create_userprofiles(dom, sipprofile):

    logger.debug("create user profiles")
    userprofile_elt_set = dom.getElementsByTagName('userprofile')
    for userprofile_elt in userprofile_elt_set:
        logger.debug("userprofile: %s" % userprofile_elt.toxml())
        email = userprofile_elt.getAttribute("email")
        logger.debug("email: %s" % email)
        account_name = userprofile_elt.getAttribute("account")
        account = Account.objects.get(name=account_name)
        logger.debug("account: %s" % account)
        first_name = userprofile_elt.getAttribute("first_name")
        last_name = userprofile_elt.getAttribute("last_name")        

        is_acct_admin_str = userprofile_elt.getAttribute("is_account_admin")
        is_acct_admin = is_acct_admin_str.lower() == 'true'

        is_active_str = userprofile_elt.getAttribute("is_active")
        is_active = is_active_str.lower() == 'true'

        is_superuser_str = userprofile_elt.getAttribute("is_superuser")
        is_superuser = is_superuser_str.lower() == 'true'

        password = userprofile_elt.getAttribute("password")

        logger.debug("creating user with email: %s" % str(email))
        user = User.objects.create_user(email, email, "password")
        user.first_name = first_name
        user.last_name = last_name
        user.is_staff = False
        user.is_active = is_active
        user.is_superuser = is_superuser   
        user.save()

        userprof = UserProfile.objects.create(
            user=user, account=account)

        if is_acct_admin:
            account.admins.add(userprof)
            account.save()

        from django.db import connection
        cursor = connection.cursor()

        cursor.execute("update auth_user set password = '%s' where id=%s" %
                       (str(password), user.id))
        
        #(password, ) = cursor.fetchone()
        #userprofile_elt.setAttribute("password", password)
                                        


def create_endpoints(dom, sipprofile):
    logger.debug("create endpoints")
    endpoint_elt_set = dom.getElementsByTagName('endpoint')
    for endpoint_elt in endpoint_elt_set:
        logger.debug("endpoint: %s" % endpoint_elt.toxml())
        userid = endpoint_elt.getAttribute("userid")
        password = endpoint_elt.getAttribute("password")

        account_name = endpoint_elt.getAttribute("account")
        account = Account.objects.get(name=account_name)
        logger.debug("account: %s" % account)
        

        email = endpoint_elt.getAttribute("userprofile")
        logger.debug("looking up user with email: %s" % email)
        user = User.objects.get(email=email)
        logger.debug("found user with email: %s" % email)        
        userprofile = user.get_profile()
        Endpoint.objects.create(userid=userid,
                                password=password,
                                account=account,
                                userprofile=userprofile)
        


def create_extensions(dom, sipprofile):

    logger.debug("create extensions")
    extension_elt_set = dom.getElementsByTagName('extension')
    for extension_elt in extension_elt_set:
        logger.debug("extension: %s" % extension_elt.toxml())

        account_name = extension_elt.getAttribute("account")
        account = Account.objects.get(name=account_name)
        logger.debug("account: %s" % account)
        
        # default to True, users can open up extensions as needed
        auth_call = True

        dest_num = extension_elt.getAttribute("dest_num")
        desc = extension_elt.getAttribute("desc")

        endpoint = None
        endpoint_userid = extension_elt.getAttribute("endpoint_userid")
        if endpoint_userid:
            endpoint = Endpoint.objects.get(account=account,
                                            userid=endpoint_userid)
            
        priority_position = extension_elt.getAttribute("priority_position")
        logger.debug("priority_position: %s" % priority_position)
        if not priority_position:
            priority_position = 0
        actions_xml = get_actions_xml(extension_elt)

        Extension.objects.create(account=account,
                                 auth_call=auth_call,
                                 dest_num=dest_num,
                                 desc=desc,
                                 endpoint=endpoint,
                                 priority_position=int(priority_position),
                                 actions_xml=actions_xml)


def get_actions_xml(extension_elt):
    actions_xml_elts = extension_elt.getElementsByTagName("actions_xml")

        
    if not actions_xml_elts:
        logger.debug("No actionss_xml_elts!!")
    else:
        actions_xml_elt = actions_xml_elts[0]
        # print "actions_xml_elt: %s" % actions_xml_elt.toxml()            

        children = actions_xml_elt.childNodes
        #print "children: %s len: %s" % (children, len(children))
        for child in children:
            #print "child: %s" % child
            if child.nodeType == child.CDATA_SECTION_NODE:
                #print "CDATA: %s" % child.nodeValue
                return child.nodeValue
            elif child.nodeType == child.TEXT_NODE:
                #print "Text: %s" % child.nodeValue
                pass

        
                    
def create_gateways(dom, sipprofile):

    logger.debug("create gateways")
    gateway_elt_set = dom.getElementsByTagName('gateway')
    for gateway_elt in gateway_elt_set:
        logger.debug("gateway: %s" % gateway_elt.toxml())
        name = gateway_elt.getAttribute("name")

        account_name = gateway_elt.getAttribute("account")
        account = Account.objects.get(name=account_name)
        logger.debug("account: %s" % account)

        username = gateway_elt.getAttribute("username")
        password = gateway_elt.getAttribute("password")
        proxy = gateway_elt.getAttribute("proxy")
        register_str = gateway_elt.getAttribute("register")
        register = (register_str.lower() == "true")
        
        extension = gateway_elt.getAttribute("extension")
        realm = gateway_elt.getAttribute("realm")
        
        from_domain = gateway_elt.getAttribute("from_domain")
        expire_seconds = gateway_elt.getAttribute("expire_seconds")
        retry_seconds = gateway_elt.getAttribute("retry_seconds")
        caller_id_in_from = gateway_elt.getAttribute("caller_id_in_from")

        SofiaGateway.objects.create(name=name,
                                    sip_profile=sipprofile,
                                    account=account,
                                    username=username,
                                    password=password,
                                    proxy=proxy,
                                    register=register,
                                    extension=extension,
                                    realm=realm,
                                    from_domain=from_domain,
                                    expire_seconds=expire_seconds,
                                    retry_seconds=retry_seconds,
                                    caller_id_in_from=caller_id_in_from,
                                    accessible_all_accts=False)


def create_accounts(root_elt, sipprofile):

    # create accounts
    logger.debug("create accounts")
    account_elt_set = root_elt.getElementsByTagName('account')
    for account_elt in account_elt_set:
        logger.debug("account: %s" % account_elt.toxml())
        name = account_elt.getAttribute("name")
        logger.debug("account name: %s" % name)

        if Account.objects.filter(name=name):
            raise Exception("Already have an account named: %s defined" % name)

        enabled_str = account_elt.getAttribute("enabled")
        enabled = (enabled_str.lower() == "true")

        domain = account_elt.getAttribute("domain")
        if not domain or len(domain) == 0:
            logger.debug("Warning: no domain for profile, using name. "
                         " You will need to fix this")
            domain = name
            
        account = Account.objects.create(name=name,
                                         enabled=enabled,
                                         domain=domain,
                                         dialout_profile=sipprofile,
                                         aliased=True)
                                         


def get_root(dom):
    for child in dom.childNodes:
        if child.nodeType == minidom.DocumentType.DOCUMENT_TYPE_NODE:
            pass
        else:
            return child


if __name__=="__main__":


    data_import_from_version_pt_5("/tmp/import.xml")
