import os
from twisted.application import internet, service
from twisted.plugin import IPlugin
from twisted.python import usage
from zope.interface import implements


class Options(usage.Options):
    """
    WikiPBX twisted plugin options.
    """
    optParameters = [
        ['settings', 's', 'wikipbx.settings', 'Django settings module']]
    optFlags = [['debug', 'd', 'Debug freeswitch events']]
    

class WikipbxServiceMaker(object):
    """
    WikiPBX service maker.
    """
    implements(service.IServiceMaker, IPlugin)

    tapname = "wikipbx"
    description = "WikiPBX service"
    options = Options
    
    def makeService(self, options):
        os.environ['DJANGO_SETTINGS_MODULE'] = options['settings']

        # TODO: uncomment code below when we'll update django
        #from django.core.management import setup_environ
        #from django.utils.importlib import import_module
        #settings_module = import_module(options['django-settings'])
        #setup_environ(settings_module)

        # Can't import some stuff until django is configured, so don't
        # place some imports in the top of the file
        from fseventlogger import EventSocketInboundFactory
        from wikipbx import modelutils
        from wikipbxweb.models import EventSocketConfig

        esconfig = EventSocketConfig.objects.all()[0]
        freeswitch_inbound_factory = EventSocketInboundFactory(
            esconfig.password, options['debug'])
        listener_service = internet.TCPClient(
            esconfig.listen_ip, esconfig.listen_port,
            freeswitch_inbound_factory)
        return listener_service


wikipbx = WikipbxServiceMaker()
