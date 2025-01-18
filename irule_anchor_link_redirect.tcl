# Anchor Link Redirect
# Author: Niels van Sluis, <niels@van-sluis.nl>
# See: https://community.f5.com/kb/codeshare/anchor-link-redirect/323408
when HTTP_REQUEST {
    # Disable the stream filter by default   
    STREAM::disable 
 
    # LTM does not uncompress response content, so if the server has compression enabled
    # and it cannot be disabled on the server, we can prevent the server from
    # sending a compressed response by removing the compression offerings from the client
    HTTP::header remove "Accept-Encoding"
    
    if { [HTTP::uri] starts_with "/f5/anchor_link_redirect" } {
        set href [b64decode [URI::query [HTTP::uri] href]]
        HTTP::respond 200 content "<html><head><title>Anchor Link Redirect</title></head><body>User clicked on link that contains a hash sign: $href</body></html>"
    }
}
	
when HTTP_RESPONSE {
    if { ([HTTP::header "Content-Type"] starts_with "text/html") } { 
        STREAM::expression {@</title>@</title>
    <script>
    document.addEventListener(`click`, e => {
      const origin = e.target.closest(`a`);

      if (origin && origin.href.indexOf('#') > -1) {
        const base64_href = btoa(origin.href);
        window.location.href = '/f5/anchor_link_redirect?href=' + base64_href;
      }
    });
    </script>@}
        STREAM::enable
    }
}
