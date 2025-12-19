when CLIENT_DATA {
    
    ############################################################################
    #+ Configuration of this iRule.
    #
    
    set PassiveDNSLearningFeeder(resolver)      "/PROD/dns_resolver"  ;# Resolver to use.
    set PassiveDNSLearningFeeder(cache_timeout) 600                   ;# Cache timeout in seconds.
    
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
        UDP::drop
        return
    }
    
    #log "Drop UDP packet since it's no longer needed"
    
    UDP::drop
    
    #log "Discontinue iRule processing if request is PTR-record."
    
    set lc_fqdn [string tolower $fqdn]
    if { $lc_fqdn ends_with ".arpa" } {
        return
    }
    
    #
    # Handler to get queried FQDN from infoblox-responses syslog message.
    ############################################################################
    
    ############################################################################
    #+ Handler to perform DNS lookup if not cached.
    #
    
    #log "Discontinue iRule processing if FQDN is found in cache."
    
    if { [table lookup -notouch -subtable fqdn_cache $lc_fqdn] != "" } {
        return
    }
    
    #log "Perform DNS lookup."
    
    RESOLVER::name_lookup $PassiveDNSLearningFeeder(resolver) $lc_fqdn a
    
    #log "Cache FQDN $lc_fqdn for 600 seconds."
    
    table set -subtable fqdn_cache $lc_fqdn 1 $PassiveDNSLearningFeeder(cache_timeout)

    #
    # Handler to perform DNS lookup if not cached.
    ############################################################################
    
    ############################################################################
    #+ Handler to report on entries in cache.
    #
    
    #log "Discontinue iRule processing if last report was done less than 1 minute ago."
    
    if { [table lookup -notouch -subtable "report" "report"] != "" } {
        return
    }
    
    table set -subtable "report" "report" 1 60
    
    log "fqdn_cache table holds [table keys -subtable fqdn_cache -count] entries."
    
    #
    # Handler to report on entries in cache.
    ############################################################################
    
}
