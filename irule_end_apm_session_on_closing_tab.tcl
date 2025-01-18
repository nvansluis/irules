# Ending an APM session when browser tab is closed 
# Author: Niels van Sluis, <niels@van-sluis.nl>
# See: https://community.f5.com/kb/codeshare/ending-an-apm-session-when-browser-tab-is-closed/325604

when CLIENT_ACCEPTED {
    ACCESS::restrict_irule_events enable
}

when HTTP_REQUEST {
    # Disable the stream filter by default   
    STREAM::disable 

    # LTM does not uncompress response content, so if the server has compression enabled
    # and it cannot be disabled on the server, we can prevent the server from
    # sending a compressed response by removing the compression offerings from the client
    HTTP::header remove "Accept-Encoding"
    
    # don't terminate an active session (a page reload will set this variable to 0 again)
    ACCESS::session data set session.custom.terminate_session 0
    
    if { [HTTP::uri] starts_with "/f5/remove_session" } {
        log local0. "DEBUG: received request to terminate session"
        ACCESS::session data set session.custom.terminate_session 1 
        
        after 1000 {
            # this session can be terminated if still inactive for 1000 ms
            if { [ACCESS::session data get session.custom.terminate_session] eq 1 } {
                log local0. "DEBUG: terminate_session"
                ACCESS::session modify -sid [ACCESS::session sid] -timeout 1
            }
        }
    }
    
    set uri [HTTP::uri]
}

when HTTP_RESPONSE {
    if { ([HTTP::header "Content-Type"] starts_with "text/html") && not ($uri starts_with "/saml/") } { 
        STREAM::expression {@</title>@</title>
    <script type="text/javascript">
      if ('sendBeacon' in navigator) {
        window.addEventListener('beforeunload', function() {
          navigator.sendBeacon(
          '/f5/remove_session',
          'All your base are belong to us');
        }, false);
      }
    </script>@}
        STREAM::enable
    }
    
    unset uri
}
