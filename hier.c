#include "auto_home.h"

void hier()
{
  c("/","etc","dnsroots.global",-1,-1,0644);

  h(auto_home,-1,-1,02755);
  d(auto_home,"bin",-1,-1,02755);

  c(auto_home,"bin","dnscache-conf",-1,-1,0755);
  c(auto_home,"bin","tinydns-conf",-1,-1,0755);
  c(auto_home,"bin","walldns-conf",-1,-1,0755);
  c(auto_home,"bin","rbldns-conf",-1,-1,0755);
  c(auto_home,"bin","pickdns-conf",-1,-1,0755);
  c(auto_home,"bin","axfrdns-conf",-1,-1,0755);

  c(auto_home,"bin","dnscache",-1,-1,0755);
  c(auto_home,"bin","tinydns",-1,-1,0755);
  c(auto_home,"bin","walldns",-1,-1,0755);
  c(auto_home,"bin","rbldns",-1,-1,0755);
  c(auto_home,"bin","pickdns",-1,-1,0755);
  c(auto_home,"bin","axfrdns",-1,-1,0755);

  c(auto_home,"bin","tinydns-get",-1,-1,0755);
  c(auto_home,"bin","tinydns-data",-1,-1,0755);
  c(auto_home,"bin","tinydns-edit",-1,-1,0755);
  c(auto_home,"bin","rbldns-data",-1,-1,0755);
  c(auto_home,"bin","pickdns-data",-1,-1,0755);
  c(auto_home,"bin","axfr-get",-1,-1,0755);

  c(auto_home,"bin","dnsip",-1,-1,0755);
  c(auto_home,"bin","dnsipq",-1,-1,0755);
  c(auto_home,"bin","dnsname",-1,-1,0755);
  c(auto_home,"bin","dnstxt",-1,-1,0755);
  c(auto_home,"bin","dnsmx",-1,-1,0755);
  c(auto_home,"bin","dnsfilter",-1,-1,0755);
  c(auto_home,"bin","random-ip",-1,-1,0755);
  c(auto_home,"bin","dnsqr",-1,-1,0755);
  c(auto_home,"bin","dnsq",-1,-1,0755);
  c(auto_home,"bin","dnstrace",-1,-1,0755);
  c(auto_home,"bin","dnstracesort",-1,-1,0755);
}
