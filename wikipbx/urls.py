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
import os
from django.conf.urls.defaults import *
from django.conf import settings
from django.contrib import admin

admin.autodiscover()

urlpatterns = patterns('',
    # You can add your own apps here e.g.:
    # (r'^foo/', include('foo.urls')),

    (r'^admin/', include(admin.site.urls)),)

# Enable static serving only for debug mode. Use your web server as front-end
# in production.
if settings.DEBUG:
    urlpatterns += patterns(
        'django.views.static',
        (r'^(fav.ico)$', 'serve',
         {'document_root': os.path.join(settings.INSTALL_SRC,
                                        'wikipbxweb/static/icons')}),
        (r'^site_media/(.*)$', 'serve',
         {'document_root': os.path.join(settings.INSTALL_SRC,
                                        'wikipbxweb/static')}),
        (r'^soundclips_media/(.*)$', 'serve',
         {'document_root': os.path.join(settings.INSTALL_ROOT, 'soundclips')}))

urlpatterns += patterns(
    'wikipbx.wikipbxweb.views',

    # General
    (r'^$', 'index'),
    (r'^dashboard/$', 'dashboard'),
    (r'^xml_dialplan/$', 'xml_dialplan'),
    (r'^memberlogin/', 'memberlogin'),
    (r'^memberlogout/$', 'memberlogout'),
    (r'^add_extension/$', 'add_extension'),

    # Extensions
    (r'^ext_priority/(?P<extension_id>\d+)/(?P<action>\S+)/$',
     'ext_priority'),
    (r'^extensions/$', 'extensions'),
    (r'^del_extension/(?P<extension_id>\d+)/$', 'del_extension'),
    (r'^edit_extension/(?P<extension_id>\d+)/$', 'edit_extension'),
    (r'^exts4endpoint/(?P<endpoint_id>\d+)/$', 'exts4endpoint'),

    # IVRs
    (r'^add_ivr/$', 'add_ivr'),
    (r'^edit_ivr/(?P<ivr_id>\d+)/$', 'edit_ivr'),
    (r'^del_ivr/(?P<ivr_id>\d+)/$', 'del_ivr'),
    (r'^ivrs/$', 'ivrs'),

    # Accounts/users
    (r'^add_account/$', 'add_account'),
    (r'^accounts/$', 'accounts'),
    (r'^users/(?P<account_id>\d+)/$', 'users'),
    (r'^add_user/(?P<account_id>\d+)/$', 'add_user'),
    (r'^edit_user/(?P<account_id>\d+)/(?P<user_id>\d+)/$', 'edit_user'),
    (r'^del_user/(?P<account_id>\d+)/(?P<user_id>\d+)/$', 'del_user'),
    (r'^del_account/(?P<account_id>\d+)/$', 'del_account'),
    (r'^edit_account/(?P<account_id>\d+)/$', 'edit_account'),

    # Sip Profiles
    (r'^add_sip_profile/$', 'add_sip_profile'),
    (r'^edit_sip_profile/(?P<profile_id>\d+)/$', 'edit_sip_profile'),
    (r'^sip_profiles/$', 'sip_profiles'),
    (r'^del_sip_profile/(?P<sip_profile_id>\d+)/$', 'del_sip_profile'),
    
    # Gateways
    (r'^add_gateway/$', 'add_gateway'),
    (r'^gateways/$', 'gateways'),
    (r'^del_gateway/(?P<gateway_id>\d+)/$', 'del_gateway'),
    (r'^edit_gateway/(?P<gateway_id>\d+)/$', 'edit_gateway'),

    # Endpoints
    (r'^add_endpoint/$', 'add_endpoint'),
    (r'^edit_endpoint/(?P<endpoint_id>\d+)/$', 'edit_endpoint'),
    (r'^endpoints/$', 'endpoints'),
    (r'^del_endpoint/(?P<endpoint_id>\d+)/$', 'del_endpoint'),                                              
    (r'^event_socket/$', 'event_socket'),
    (r'^outgoing2endpoint/(?P<endpoint_id>\d+)/$', 'outgoing2endpoint'),

    # Soundclips
    (r'^add_soundclip/$', 'add_soundclip'),
    (r'^soundclips/$', 'soundclips'),
    (r'^del_soundclip/(?P<soundclip_id>\d+)/$', 'del_soundclip'),

    # CDRs
    (r'^add_cdr/$', 'add_cdr'),
    (r'^completedcalls/$', 'completedcalls'),
    (r'^completedcalls/page/(?P<page>\d+)/$', 'completedcalls'),

    # Server settings/logs
    (r'^server_logs/$', 'server_logs'),
    (r'^server_logs/page/(?P<page>\d+)/$', 'server_logs'),
    (r'^add_root/$', 'add_root'),
    (r'^migrate_import/$', 'migrate_import'),

    # Freeswitch control
    (r'^livecalls/$', 'livecalls'),
    (r'^hangup_channels/(?P<chan_uuid>\S+)/$', 'hangup_channels'),
    (r'^hangup_channels/$', 'hangup_channels'),
    (r'^dialout/(?P<dest_ext_app>\S+)/$', 'dialout'),
    # (r'^broadcast2channel/(?P<chan_uuid>\S+)/(?P<soundclip_id>\d+)/$',
    #'broadcast2channel'),
    (r'^broadcast2channel/(?P<chan_uuid>\S+)/$', 'broadcast2channel'),
    (r'^transfer/(?P<chan_uuid>\S+)/$', 'transfer'),

    # Mailserver
    (r'^config_mailserver/$', 'config_mailserver'),
    (r'^test_mailserver/$', 'test_mailserver'),
)
