def global_processor(request):
    result = {}

    infomsg = request.REQUEST.get('infomsg', None)
    if infomsg:
        result['infomsg'] = infomsg
        
    urgentmsg = request.REQUEST.get('urgentmsg', None)
    if urgentmsg:
        result['urgentmsg'] = urgentmsg

    # DON'T catch exceptions below - let it be propagated and fixed
    user = request.user
    if (not (user and not user.is_anonymous() and user.is_superuser)
        and (user and not user.is_anonymous() and
             user.is_authenticated())):
        profile = user.get_profile()
        if profile:
            result['account'] = profile.account    

    return result
    
