when CLIENT_DATA {
    
    ############################################################################
    #+ Configuration of this iRule.
    #
    
    set PassiveDNSLearningFeeder(resolver)      "/Common/dns_resolver"  ;# Resolver to use.
    set PassiveDNSLearningFeeder(cache_timeout) 60                      ;# Cache timeout in seconds.
    
    #
    # Configuration of this iRule.
    ############################################################################

    ############################################################################
    #+ Handler to get queried FQDN from infoblox-responses syslog message.
    #
    # Example infoblox-responses syslog message:
    # <30>Dec 17 13:58:40 192.168.178.123 named[90581]: infoblox-responses: 17-Dec-2025 13:58:40.811 client 192.168.178.55#55720: UDP: query: www.van-sluis.nl IN A response: NOERROR +EV www.van-sluis.nl. 250 IN A 188.114.97.0; www.van-sluis.nl. 250 IN A 188.114.96.0;

    #log "Discontinue iRule processing if log type isn't of type infoblox-responses."
    
    if { not([scan [UDP::payload] {%*[^]]%*[^:]: %[^:]%*[^#]%*[^y]y: %s} type fqdn] == 2 && $type == "infoblox-responses") } {
        return
    }
    
    #
    # Handler to get queried FQDN from infoblox-responses syslog message.
    ############################################################################
    
    ############################################################################
    #+ Handler to perform DNS lookup if not cached.
    #
    
    #log "Discontinue iRule processing if FQDN is found in cache."
    
    if { [table lookup -notouch -subtable fqdn_cache $fqdn] != "" } {
        return
    }
    
    #log "Perform DNS lookup."
    
    RESOLVER::name_lookup $PassiveDNSLearningFeeder(resolver) $fqdn a
    
    #log "Cache FQDN for 60 seconds."
    
    table set -subtable fqdn_cache $fqdn 1 $PassiveDNSLearningFeeder(cache_timeout)

    #
    # Handler to perform DNS lookup if not cached.
    ############################################################################
    
}
