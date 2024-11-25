# ACME iRule 
# Installed in the F5 DNS Device, in the DNS Listener.
# Description: This iRule is in charge of responding to any TXT DNS Request which begins with _acme-challenge.
#     1. It removes the domain delegation .gslb.
#     2. Check the FQDN on the LTM where the ACME client is running
#     3. Create a sideband on the LTM VIP of such FQDN to query the challenge
#        3.1. The LTM VIP respond the challenge
#     4. The F5 DNS device respond to the ACME server the TXT record including the ACME challenge.


when RULE_INIT {
   set static::DEBUGACME 1
}
when DNS_REQUEST priority 2 {
   #_acme-challenge.example.org. 300 IN TXT “gfj9Xq…Rg85nM”
   if {([DNS::question type] eq "TXT") && ([DNS::question name] starts_with "_acme-challenge") } {
      #set domain [substr [DNS::question name] 16]
      set domain [string map {_acme-challenge. "" gslb. ""} [DNS::question name]]
      if { $static::DEBUGACME } {
         log local0. "0. Domain without delegation: $domain"
      }
      set ltm_ip [class lookup $domain dg_ltm]
      if { $ltm_ip eq "" } {
         if { $static::DEBUGACME } {
            log local0. "No ltm assigned to FQDN"
         }
         return
      } else {
         if { $static::DEBUGACME } {
            log local0. "1. Running GET to http://$ltm_ip/acme_challenge/$domain"
         }
         set sts [call /Common/HSSR::http_req -uri "http://$ltm_ip/acme_challenge/$domain" \
            -tag "getX" -rbody rbody]
         if { $static::DEBUGACME } {
            log local0.info "1.1. server returned status=${sts}, content=${rbody}"
         }
      }
      #set response_content_all [class lookup $domain dg_acme_challenge]
      set response_content_all $rbody
      if { $response_content_all contains {|} } {
         log local0. "2. ACME challenge contains '|': $response_content_all"
         if { [table set -excl -- ${domain}_wildcard 1 10 10] <= 5  } {
            # Respond first field
            table incr -- ${domain}_wildcard 1
            set response_content [getfield $response_content_all | 2]
            if { $static::DEBUGACME } {
               log local0. "2.1. Responding: $response_content"
            }
         } else {
            #Respond second field
            set response_content [getfield $response_content_all | 1]
            if { $static::DEBUGACME } {
               log local0. "2.2. Responding: $response_content"
            }
         }
      } else {
         set response_content $response_content_all
         if { $static::DEBUGACME } {
            log local0. "2.3. Responding: $response_content"
         }
      }
      if {$response_content ne ""} {
         if { $static::DEBUGACME } {
            log local0. "3. Good ACME response: All: $response_content_all Specific: $response_content"
         }
         DNS::answer insert "[DNS::question name]. 60 [DNS::question class]  [DNS::question type] $response_content"
         DNS::return
      } else {
         if { $static::DEBUGACME } {
            log local0. "4. Bad ACME request requested for [substr [DNS::question name] 16]"
         }
      }
      unset response_content
      event disable all
      return
   }
}