# Don't edit Makefile! Use conf-* for configuration.

SHELL=/bin/sh

default: it

alloc.a: \
makelib alloc.o alloc_re.o getln.o getln2.o stralloc_cat.o \
stralloc_catb.o stralloc_cats.o stralloc_copy.o stralloc_eady.o \
stralloc_num.o stralloc_opyb.o stralloc_opys.o stralloc_pend.o
	./makelib alloc.a alloc.o alloc_re.o getln.o getln2.o \
	stralloc_cat.o stralloc_catb.o stralloc_cats.o \
	stralloc_copy.o stralloc_eady.o stralloc_num.o \
	stralloc_opyb.o stralloc_opys.o stralloc_pend.o

alloc.o: \
compile alloc.c alloc.h error.h
	./compile alloc.c

alloc_re.o: \
compile alloc_re.c alloc.h byte.h
	./compile alloc_re.c

auto-str: \
load auto-str.o buffer.a unix.a byte.a
	./load auto-str buffer.a unix.a byte.a 

auto-str.o: \
compile auto-str.c buffer.h exit.h
	./compile auto-str.c

auto_home.c: \
auto-str conf-home
	./auto-str auto_home `head -1 conf-home` > auto_home.c

auto_home.o: \
compile auto_home.c
	./compile auto_home.c

axfr-get: \
load axfr-get.o iopause.o timeoutread.o timeoutwrite.o dns.a libtai.a \
alloc.a buffer.a unix.a byte.a
	./load axfr-get iopause.o timeoutread.o timeoutwrite.o \
	dns.a libtai.a alloc.a buffer.a unix.a byte.a 

axfr-get.o: \
compile axfr-get.c uint32.h uint16.h stralloc.h gen_alloc.h error.h \
strerr.h getln.h buffer.h stralloc.h buffer.h exit.h open.h scan.h \
byte.h str.h ip4.h timeoutread.h timeoutwrite.h dns.h stralloc.h \
iopause.h taia.h tai.h uint64.h taia.h
	./compile axfr-get.c

axfrdns: \
load axfrdns.o iopause.o droproot.o tdlookup.o response.o qlog.o \
prot.o timeoutread.o timeoutwrite.o dns.a libtai.a alloc.a env.a \
cdb.a buffer.a unix.a byte.a
	./load axfrdns iopause.o droproot.o tdlookup.o response.o \
	qlog.o prot.o timeoutread.o timeoutwrite.o dns.a libtai.a \
	alloc.a env.a cdb.a buffer.a unix.a byte.a 

axfrdns-conf: \
load axfrdns-conf.o generic-conf.o auto_home.o buffer.a unix.a byte.a
	./load axfrdns-conf generic-conf.o auto_home.o buffer.a \
	unix.a byte.a 

axfrdns-conf.o: \
compile axfrdns-conf.c strerr.h exit.h auto_home.h generic-conf.h \
buffer.h
	./compile axfrdns-conf.c

axfrdns.o: \
compile axfrdns.c droproot.h exit.h env.h uint32.h uint16.h ip4.h \
tai.h uint64.h buffer.h timeoutread.h timeoutwrite.h open.h seek.h \
cdb.h uint32.h stralloc.h gen_alloc.h strerr.h str.h byte.h case.h \
dns.h stralloc.h iopause.h taia.h tai.h taia.h scan.h qlog.h uint16.h \
response.h uint32.h
	./compile axfrdns.c

buffer.a: \
makelib buffer.o buffer_1.o buffer_2.o buffer_copy.o buffer_get.o \
buffer_put.o strerr_die.o strerr_sys.o
	./makelib buffer.a buffer.o buffer_1.o buffer_2.o \
	buffer_copy.o buffer_get.o buffer_put.o strerr_die.o \
	strerr_sys.o

buffer.o: \
compile buffer.c buffer.h
	./compile buffer.c

buffer_1.o: \
compile buffer_1.c buffer.h
	./compile buffer_1.c

buffer_2.o: \
compile buffer_2.c buffer.h
	./compile buffer_2.c

buffer_copy.o: \
compile buffer_copy.c buffer.h
	./compile buffer_copy.c

buffer_get.o: \
compile buffer_get.c buffer.h byte.h error.h
	./compile buffer_get.c

buffer_put.o: \
compile buffer_put.c buffer.h str.h byte.h error.h
	./compile buffer_put.c

buffer_read.o: \
compile buffer_read.c buffer.h
	./compile buffer_read.c

buffer_write.o: \
compile buffer_write.c buffer.h
	./compile buffer_write.c

byte.a: \
makelib byte_chr.o byte_copy.o byte_cr.o byte_diff.o byte_zero.o \
case_diffb.o case_diffs.o case_lowerb.o fmt_ulong.o ip4_fmt.o \
ip4_scan.o scan_ulong.o str_chr.o str_diff.o str_len.o str_rchr.o \
str_start.o uint16_pack.o uint16_unpack.o uint32_pack.o \
uint32_unpack.o
	./makelib byte.a byte_chr.o byte_copy.o byte_cr.o \
	byte_diff.o byte_zero.o case_diffb.o case_diffs.o \
	case_lowerb.o fmt_ulong.o ip4_fmt.o ip4_scan.o scan_ulong.o \
	str_chr.o str_diff.o str_len.o str_rchr.o str_start.o \
	uint16_pack.o uint16_unpack.o uint32_pack.o uint32_unpack.o

byte_chr.o: \
compile byte_chr.c byte.h
	./compile byte_chr.c

byte_copy.o: \
compile byte_copy.c byte.h
	./compile byte_copy.c

byte_cr.o: \
compile byte_cr.c byte.h
	./compile byte_cr.c

byte_diff.o: \
compile byte_diff.c byte.h
	./compile byte_diff.c

byte_zero.o: \
compile byte_zero.c byte.h
	./compile byte_zero.c

cache.o: \
compile cache.c alloc.h byte.h uint32.h exit.h tai.h uint64.h cache.h \
uint32.h uint64.h
	./compile cache.c

cachetest: \
load cachetest.o cache.o libtai.a buffer.a alloc.a unix.a byte.a
	./load cachetest cache.o libtai.a buffer.a alloc.a unix.a \
	byte.a 

cachetest.o: \
compile cachetest.c buffer.h exit.h cache.h uint32.h uint64.h str.h
	./compile cachetest.c

case_diffb.o: \
compile case_diffb.c case.h
	./compile case_diffb.c

case_diffs.o: \
compile case_diffs.c case.h
	./compile case_diffs.c

case_lowerb.o: \
compile case_lowerb.c case.h
	./compile case_lowerb.c

cdb.a: \
makelib cdb.o cdb_hash.o cdb_make.o
	./makelib cdb.a cdb.o cdb_hash.o cdb_make.o

cdb.o: \
compile cdb.c error.h seek.h byte.h cdb.h uint32.h
	./compile cdb.c

cdb_hash.o: \
compile cdb_hash.c cdb.h uint32.h
	./compile cdb_hash.c

cdb_make.o: \
compile cdb_make.c seek.h error.h alloc.h cdb.h uint32.h cdb_make.h \
buffer.h uint32.h
	./compile cdb_make.c

check: \
it instcheck
	./instcheck

chkshsgr: \
load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: \
compile chkshsgr.c exit.h
	./compile chkshsgr.c

choose: \
warn-auto.sh choose.sh conf-home
	cat warn-auto.sh choose.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> choose
	chmod 755 choose

compile: \
warn-auto.sh conf-cc
	( cat warn-auto.sh; \
	echo exec "`head -1 conf-cc`" '-c $${1+"$$@"}' \
	) > compile
	chmod 755 compile

dd.o: \
compile dd.c dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h \
uint64.h taia.h dd.h
	./compile dd.c

direntry.h: \
choose compile trydrent.c direntry.h1 direntry.h2
	./choose c trydrent direntry.h1 direntry.h2 > direntry.h

dns.a: \
makelib dns_dfd.o dns_domain.o dns_dtda.o dns_ip.o dns_ipq.o dns_mx.o \
dns_name.o dns_nd.o dns_packet.o dns_random.o dns_rcip.o dns_rcrw.o \
dns_resolve.o dns_sortip.o dns_transmit.o dns_txt.o
	./makelib dns.a dns_dfd.o dns_domain.o dns_dtda.o dns_ip.o \
	dns_ipq.o dns_mx.o dns_name.o dns_nd.o dns_packet.o \
	dns_random.o dns_rcip.o dns_rcrw.o dns_resolve.o \
	dns_sortip.o dns_transmit.o dns_txt.o

dns_dfd.o: \
compile dns_dfd.c error.h alloc.h byte.h dns.h stralloc.h gen_alloc.h \
iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_dfd.c

dns_domain.o: \
compile dns_domain.c error.h alloc.h case.h byte.h dns.h stralloc.h \
gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_domain.c

dns_dtda.o: \
compile dns_dtda.c stralloc.h gen_alloc.h dns.h stralloc.h iopause.h \
taia.h tai.h uint64.h taia.h
	./compile dns_dtda.c

dns_ip.o: \
compile dns_ip.c stralloc.h gen_alloc.h uint16.h byte.h dns.h \
stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_ip.c

dns_ipq.o: \
compile dns_ipq.c stralloc.h gen_alloc.h case.h byte.h str.h dns.h \
stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_ipq.c

dns_mx.o: \
compile dns_mx.c stralloc.h gen_alloc.h byte.h uint16.h dns.h \
stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_mx.c

dns_name.o: \
compile dns_name.c stralloc.h gen_alloc.h uint16.h byte.h dns.h \
stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_name.c

dns_nd.o: \
compile dns_nd.c byte.h fmt.h dns.h stralloc.h gen_alloc.h iopause.h \
taia.h tai.h uint64.h taia.h
	./compile dns_nd.c

dns_packet.o: \
compile dns_packet.c error.h dns.h stralloc.h gen_alloc.h iopause.h \
taia.h tai.h uint64.h taia.h
	./compile dns_packet.c

dns_random.o: \
compile dns_random.c dns.h stralloc.h gen_alloc.h iopause.h taia.h \
tai.h uint64.h taia.h taia.h uint32.h
	./compile dns_random.c

dns_rcip.o: \
compile dns_rcip.c taia.h tai.h uint64.h openreadclose.h stralloc.h \
gen_alloc.h byte.h ip4.h env.h dns.h stralloc.h iopause.h taia.h \
taia.h
	./compile dns_rcip.c

dns_rcrw.o: \
compile dns_rcrw.c taia.h tai.h uint64.h env.h byte.h str.h \
openreadclose.h stralloc.h gen_alloc.h dns.h stralloc.h iopause.h \
taia.h taia.h
	./compile dns_rcrw.c

dns_resolve.o: \
compile dns_resolve.c iopause.h taia.h tai.h uint64.h taia.h byte.h \
dns.h stralloc.h gen_alloc.h iopause.h taia.h
	./compile dns_resolve.c

dns_sortip.o: \
compile dns_sortip.c byte.h dns.h stralloc.h gen_alloc.h iopause.h \
taia.h tai.h uint64.h taia.h
	./compile dns_sortip.c

dns_transmit.o: \
compile dns_transmit.c socket.h uint16.h alloc.h error.h byte.h \
uint16.h dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h \
taia.h
	./compile dns_transmit.c

dns_txt.o: \
compile dns_txt.c stralloc.h gen_alloc.h uint16.h byte.h dns.h \
stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dns_txt.c

dnscache: \
load dnscache.o droproot.o okclient.o log.o cache.o query.o \
response.o dd.o roots.o iopause.o prot.o dns.a env.a alloc.a buffer.a \
libtai.a unix.a byte.a socket.lib
	./load dnscache droproot.o okclient.o log.o cache.o \
	query.o response.o dd.o roots.o iopause.o prot.o dns.a \
	env.a alloc.a buffer.a libtai.a unix.a byte.a  `cat \
	socket.lib`

dnscache-conf: \
load dnscache-conf.o generic-conf.o auto_home.o libtai.a buffer.a \
unix.a byte.a
	./load dnscache-conf generic-conf.o auto_home.o libtai.a \
	buffer.a unix.a byte.a 

dnscache-conf.o: \
compile dnscache-conf.c hasdevtcp.h strerr.h buffer.h uint32.h taia.h \
tai.h uint64.h str.h open.h error.h exit.h auto_home.h generic-conf.h \
buffer.h
	./compile dnscache-conf.c

dnscache.o: \
compile dnscache.c env.h exit.h scan.h strerr.h error.h ip4.h \
uint16.h uint64.h socket.h uint16.h dns.h stralloc.h gen_alloc.h \
iopause.h taia.h tai.h uint64.h taia.h taia.h byte.h roots.h fmt.h \
iopause.h query.h dns.h uint32.h alloc.h response.h uint32.h cache.h \
uint32.h uint64.h ndelay.h log.h uint64.h okclient.h droproot.h
	./compile dnscache.c

dnsfilter: \
load dnsfilter.o iopause.o getopt.a dns.a env.a libtai.a alloc.a \
buffer.a unix.a byte.a socket.lib
	./load dnsfilter iopause.o getopt.a dns.a env.a libtai.a \
	alloc.a buffer.a unix.a byte.a  `cat socket.lib`

dnsfilter.o: \
compile dnsfilter.c strerr.h buffer.h stralloc.h gen_alloc.h alloc.h \
dns.h stralloc.h iopause.h taia.h tai.h uint64.h taia.h ip4.h byte.h \
scan.h taia.h sgetopt.h subgetopt.h iopause.h error.h exit.h
	./compile dnsfilter.c

dnsip: \
load dnsip.o iopause.o dns.a env.a libtai.a alloc.a buffer.a unix.a \
byte.a socket.lib
	./load dnsip iopause.o dns.a env.a libtai.a alloc.a \
	buffer.a unix.a byte.a  `cat socket.lib`

dnsip.o: \
compile dnsip.c buffer.h exit.h strerr.h ip4.h dns.h stralloc.h \
gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dnsip.c

dnsipq: \
load dnsipq.o iopause.o dns.a env.a libtai.a alloc.a buffer.a unix.a \
byte.a socket.lib
	./load dnsipq iopause.o dns.a env.a libtai.a alloc.a \
	buffer.a unix.a byte.a  `cat socket.lib`

dnsipq.o: \
compile dnsipq.c buffer.h exit.h strerr.h ip4.h dns.h stralloc.h \
gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dnsipq.c

dnsmx: \
load dnsmx.o iopause.o dns.a env.a libtai.a alloc.a buffer.a unix.a \
byte.a socket.lib
	./load dnsmx iopause.o dns.a env.a libtai.a alloc.a \
	buffer.a unix.a byte.a  `cat socket.lib`

dnsmx.o: \
compile dnsmx.c buffer.h exit.h strerr.h uint16.h byte.h str.h fmt.h \
dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dnsmx.c

dnsname: \
load dnsname.o iopause.o dns.a env.a libtai.a alloc.a buffer.a unix.a \
byte.a socket.lib
	./load dnsname iopause.o dns.a env.a libtai.a alloc.a \
	buffer.a unix.a byte.a  `cat socket.lib`

dnsname.o: \
compile dnsname.c buffer.h exit.h strerr.h ip4.h dns.h stralloc.h \
gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dnsname.c

dnsq: \
load dnsq.o iopause.o printrecord.o printpacket.o parsetype.o dns.a \
env.a libtai.a buffer.a alloc.a unix.a byte.a socket.lib
	./load dnsq iopause.o printrecord.o printpacket.o \
	parsetype.o dns.a env.a libtai.a buffer.a alloc.a unix.a \
	byte.a  `cat socket.lib`

dnsq.o: \
compile dnsq.c uint16.h strerr.h buffer.h scan.h str.h byte.h error.h \
ip4.h iopause.h taia.h tai.h uint64.h printpacket.h stralloc.h \
gen_alloc.h parsetype.h dns.h stralloc.h iopause.h taia.h
	./compile dnsq.c

dnsqr: \
load dnsqr.o iopause.o printrecord.o printpacket.o parsetype.o dns.a \
env.a libtai.a buffer.a alloc.a unix.a byte.a socket.lib
	./load dnsqr iopause.o printrecord.o printpacket.o \
	parsetype.o dns.a env.a libtai.a buffer.a alloc.a unix.a \
	byte.a  `cat socket.lib`

dnsqr.o: \
compile dnsqr.c uint16.h strerr.h buffer.h scan.h str.h byte.h \
error.h iopause.h taia.h tai.h uint64.h printpacket.h stralloc.h \
gen_alloc.h parsetype.h dns.h stralloc.h iopause.h taia.h
	./compile dnsqr.c

dnstrace: \
load dnstrace.o dd.o iopause.o printrecord.o parsetype.o dns.a env.a \
libtai.a alloc.a buffer.a unix.a byte.a socket.lib
	./load dnstrace dd.o iopause.o printrecord.o parsetype.o \
	dns.a env.a libtai.a alloc.a buffer.a unix.a byte.a  `cat \
	socket.lib`

dnstrace.o: \
compile dnstrace.c uint16.h uint32.h fmt.h str.h byte.h ip4.h \
gen_alloc.h gen_allocdefs.h exit.h buffer.h stralloc.h gen_alloc.h \
error.h strerr.h iopause.h taia.h tai.h uint64.h printrecord.h \
stralloc.h alloc.h parsetype.h dd.h dns.h stralloc.h iopause.h taia.h
	./compile dnstrace.c

dnstracesort: \
warn-auto.sh dnstracesort.sh conf-home
	cat warn-auto.sh dnstracesort.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> dnstracesort
	chmod 755 dnstracesort

dnstxt: \
load dnstxt.o iopause.o dns.a env.a libtai.a alloc.a buffer.a unix.a \
byte.a socket.lib
	./load dnstxt iopause.o dns.a env.a libtai.a alloc.a \
	buffer.a unix.a byte.a  `cat socket.lib`

dnstxt.o: \
compile dnstxt.c buffer.h exit.h strerr.h dns.h stralloc.h \
gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile dnstxt.c

droproot.o: \
compile droproot.c env.h scan.h prot.h strerr.h
	./compile droproot.c

env.a: \
makelib env.o
	./makelib env.a env.o

env.o: \
compile env.c str.h env.h
	./compile env.c

error.o: \
compile error.c error.h
	./compile error.c

error_str.o: \
compile error_str.c error.h
	./compile error_str.c

fmt_ulong.o: \
compile fmt_ulong.c fmt.h
	./compile fmt_ulong.c

generic-conf.o: \
compile generic-conf.c strerr.h buffer.h open.h generic-conf.h \
buffer.h
	./compile generic-conf.c

getln.o: \
compile getln.c byte.h getln.h buffer.h stralloc.h gen_alloc.h
	./compile getln.c

getln2.o: \
compile getln2.c byte.h getln.h buffer.h stralloc.h gen_alloc.h
	./compile getln2.c

getopt.a: \
makelib sgetopt.o subgetopt.o
	./makelib getopt.a sgetopt.o subgetopt.o

hasdevtcp.h: \
systype hasdevtcp.h1 hasdevtcp.h2
	( case "`cat systype`" in \
	  sunos-5.*) cat hasdevtcp.h2 ;; \
	  *) cat hasdevtcp.h1 ;; \
	esac ) > hasdevtcp.h

hasshsgr.h: \
choose compile load tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr \
warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

hier.o: \
compile hier.c auto_home.h
	./compile hier.c

install: \
load install.o hier.o auto_home.o buffer.a unix.a byte.a
	./load install hier.o auto_home.o buffer.a unix.a byte.a 

install.o: \
compile install.c buffer.h strerr.h error.h open.h exit.h
	./compile install.c

instcheck: \
load instcheck.o hier.o auto_home.o buffer.a unix.a byte.a
	./load instcheck hier.o auto_home.o buffer.a unix.a byte.a 

instcheck.o: \
compile instcheck.c strerr.h error.h exit.h
	./compile instcheck.c

iopause.h: \
choose compile load trypoll.c iopause.h1 iopause.h2
	./choose clr trypoll iopause.h1 iopause.h2 > iopause.h

iopause.o: \
compile iopause.c taia.h tai.h uint64.h select.h iopause.h taia.h
	./compile iopause.c

ip4_fmt.o: \
compile ip4_fmt.c fmt.h ip4.h
	./compile ip4_fmt.c

ip4_scan.o: \
compile ip4_scan.c scan.h ip4.h
	./compile ip4_scan.c

it: \
prog install instcheck

libtai.a: \
makelib tai_add.o tai_now.o tai_pack.o tai_sub.o tai_uint.o \
tai_unpack.o taia_add.o taia_approx.o taia_frac.o taia_less.o \
taia_now.o taia_pack.o taia_sub.o taia_tai.o taia_uint.o
	./makelib libtai.a tai_add.o tai_now.o tai_pack.o \
	tai_sub.o tai_uint.o tai_unpack.o taia_add.o taia_approx.o \
	taia_frac.o taia_less.o taia_now.o taia_pack.o taia_sub.o \
	taia_tai.o taia_uint.o

load: \
warn-auto.sh conf-ld
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo exec "`head -1 conf-ld`" \
	'-o "$$main" "$$main".o $${1+"$$@"}' \
	) > load
	chmod 755 load

log.o: \
compile log.c buffer.h uint32.h uint16.h error.h byte.h log.h \
uint64.h
	./compile log.c

makelib: \
warn-auto.sh systype
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo 'rm -f "$$main"'; \
	echo 'ar cr "$$main" $${1+"$$@"}'; \
	case "`cat systype`" in \
	sunos-5.*) ;; \
	unix_sv*) ;; \
	irix64-*) ;; \
	irix-*) ;; \
	dgux-*) ;; \
	hp-ux-*) ;; \
	sco*) ;; \
	*) echo 'ranlib "$$main"' ;; \
	esac \
	) > makelib
	chmod 755 makelib

ndelay_off.o: \
compile ndelay_off.c ndelay.h
	./compile ndelay_off.c

ndelay_on.o: \
compile ndelay_on.c ndelay.h
	./compile ndelay_on.c

okclient.o: \
compile okclient.c str.h ip4.h okclient.h
	./compile okclient.c

open_read.o: \
compile open_read.c open.h
	./compile open_read.c

open_trunc.o: \
compile open_trunc.c open.h
	./compile open_trunc.c

openreadclose.o: \
compile openreadclose.c error.h open.h readclose.h stralloc.h \
gen_alloc.h openreadclose.h stralloc.h
	./compile openreadclose.c

parsetype.o: \
compile parsetype.c scan.h byte.h case.h dns.h stralloc.h gen_alloc.h \
iopause.h taia.h tai.h uint64.h taia.h uint16.h parsetype.h
	./compile parsetype.c

pickdns: \
load pickdns.o server.o response.o droproot.o qlog.o prot.o dns.a \
env.a libtai.a cdb.a alloc.a buffer.a unix.a byte.a socket.lib
	./load pickdns server.o response.o droproot.o qlog.o \
	prot.o dns.a env.a libtai.a cdb.a alloc.a buffer.a unix.a \
	byte.a  `cat socket.lib`

pickdns-conf: \
load pickdns-conf.o generic-conf.o auto_home.o buffer.a unix.a byte.a
	./load pickdns-conf generic-conf.o auto_home.o buffer.a \
	unix.a byte.a 

pickdns-conf.o: \
compile pickdns-conf.c strerr.h exit.h auto_home.h generic-conf.h \
buffer.h
	./compile pickdns-conf.c

pickdns-data: \
load pickdns-data.o cdb.a dns.a alloc.a buffer.a unix.a byte.a
	./load pickdns-data cdb.a dns.a alloc.a buffer.a unix.a \
	byte.a 

pickdns-data.o: \
compile pickdns-data.c buffer.h exit.h cdb_make.h buffer.h uint32.h \
open.h alloc.h gen_allocdefs.h stralloc.h gen_alloc.h getln.h \
buffer.h stralloc.h case.h strerr.h str.h byte.h scan.h fmt.h ip4.h \
dns.h stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile pickdns-data.c

pickdns.o: \
compile pickdns.c byte.h case.h dns.h stralloc.h gen_alloc.h \
iopause.h taia.h tai.h uint64.h taia.h open.h cdb.h uint32.h \
response.h uint32.h
	./compile pickdns.c

printpacket.o: \
compile printpacket.c uint16.h uint32.h error.h byte.h dns.h \
stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h \
printrecord.h stralloc.h printpacket.h stralloc.h
	./compile printpacket.c

printrecord.o: \
compile printrecord.c uint16.h uint32.h error.h byte.h dns.h \
stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h \
printrecord.h stralloc.h
	./compile printrecord.c

prog: \
dnscache-conf dnscache walldns-conf walldns rbldns-conf rbldns \
rbldns-data pickdns-conf pickdns pickdns-data tinydns-conf tinydns \
tinydns-data tinydns-get tinydns-edit axfr-get axfrdns-conf axfrdns \
dnsip dnsipq dnsname dnstxt dnsmx dnsfilter random-ip dnsqr dnsq \
dnstrace dnstracesort cachetest utime rts

prot.o: \
compile prot.c hasshsgr.h prot.h
	./compile prot.c

qlog.o: \
compile qlog.c buffer.h qlog.h uint16.h
	./compile qlog.c

query.o: \
compile query.c error.h roots.h log.h uint64.h case.h cache.h \
uint32.h uint64.h byte.h dns.h stralloc.h gen_alloc.h iopause.h \
taia.h tai.h uint64.h taia.h uint64.h uint32.h uint16.h dd.h alloc.h \
response.h uint32.h query.h dns.h uint32.h
	./compile query.c

random-ip: \
load random-ip.o dns.a libtai.a buffer.a unix.a byte.a
	./load random-ip dns.a libtai.a buffer.a unix.a byte.a 

random-ip.o: \
compile random-ip.c buffer.h exit.h fmt.h scan.h dns.h stralloc.h \
gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile random-ip.c

rbldns: \
load rbldns.o server.o response.o dd.o droproot.o qlog.o prot.o dns.a \
env.a libtai.a cdb.a alloc.a buffer.a unix.a byte.a socket.lib
	./load rbldns server.o response.o dd.o droproot.o qlog.o \
	prot.o dns.a env.a libtai.a cdb.a alloc.a buffer.a unix.a \
	byte.a  `cat socket.lib`

rbldns-conf: \
load rbldns-conf.o generic-conf.o auto_home.o buffer.a unix.a byte.a
	./load rbldns-conf generic-conf.o auto_home.o buffer.a \
	unix.a byte.a 

rbldns-conf.o: \
compile rbldns-conf.c strerr.h exit.h auto_home.h generic-conf.h \
buffer.h
	./compile rbldns-conf.c

rbldns-data: \
load rbldns-data.o cdb.a alloc.a buffer.a unix.a byte.a
	./load rbldns-data cdb.a alloc.a buffer.a unix.a byte.a 

rbldns-data.o: \
compile rbldns-data.c buffer.h exit.h cdb_make.h buffer.h uint32.h \
open.h stralloc.h gen_alloc.h getln.h buffer.h stralloc.h strerr.h \
byte.h scan.h fmt.h ip4.h
	./compile rbldns-data.c

rbldns.o: \
compile rbldns.c str.h byte.h ip4.h open.h env.h cdb.h uint32.h dns.h \
stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h dd.h \
strerr.h response.h uint32.h
	./compile rbldns.c

readclose.o: \
compile readclose.c error.h readclose.h stralloc.h gen_alloc.h
	./compile readclose.c

response.o: \
compile response.c dns.h stralloc.h gen_alloc.h iopause.h taia.h \
tai.h uint64.h taia.h byte.h uint16.h response.h uint32.h
	./compile response.c

roots.o: \
compile roots.c open.h error.h str.h byte.h error.h direntry.h ip4.h \
dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h taia.h \
openreadclose.h stralloc.h roots.h
	./compile roots.c

rts: \
warn-auto.sh rts.sh conf-home
	cat warn-auto.sh rts.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> rts
	chmod 755 rts

scan_ulong.o: \
compile scan_ulong.c scan.h
	./compile scan_ulong.c

seek_set.o: \
compile seek_set.c seek.h
	./compile seek_set.c

select.h: \
choose compile trysysel.c select.h1 select.h2
	./choose c trysysel select.h1 select.h2 > select.h

server.o: \
compile server.c byte.h case.h env.h buffer.h strerr.h ip4.h uint16.h \
ndelay.h socket.h uint16.h droproot.h qlog.h uint16.h response.h \
uint32.h dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h uint64.h \
taia.h
	./compile server.c

setup: \
it install
	./install

sgetopt.o: \
compile sgetopt.c buffer.h sgetopt.h subgetopt.h subgetopt.h
	./compile sgetopt.c

socket.lib: \
trylsock.c compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

socket_accept.o: \
compile socket_accept.c byte.h socket.h uint16.h
	./compile socket_accept.c

socket_bind.o: \
compile socket_bind.c byte.h socket.h uint16.h
	./compile socket_bind.c

socket_conn.o: \
compile socket_conn.c byte.h socket.h uint16.h
	./compile socket_conn.c

socket_listen.o: \
compile socket_listen.c socket.h uint16.h
	./compile socket_listen.c

socket_recv.o: \
compile socket_recv.c byte.h socket.h uint16.h
	./compile socket_recv.c

socket_send.o: \
compile socket_send.c byte.h socket.h uint16.h
	./compile socket_send.c

socket_tcp.o: \
compile socket_tcp.c ndelay.h socket.h uint16.h
	./compile socket_tcp.c

socket_udp.o: \
compile socket_udp.c ndelay.h socket.h uint16.h
	./compile socket_udp.c

str_chr.o: \
compile str_chr.c str.h
	./compile str_chr.c

str_diff.o: \
compile str_diff.c str.h
	./compile str_diff.c

str_len.o: \
compile str_len.c str.h
	./compile str_len.c

str_rchr.o: \
compile str_rchr.c str.h
	./compile str_rchr.c

str_start.o: \
compile str_start.c str.h
	./compile str_start.c

stralloc_cat.o: \
compile stralloc_cat.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_cat.c

stralloc_catb.o: \
compile stralloc_catb.c stralloc.h gen_alloc.h byte.h
	./compile stralloc_catb.c

stralloc_cats.o: \
compile stralloc_cats.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_cats.c

stralloc_copy.o: \
compile stralloc_copy.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_copy.c

stralloc_eady.o: \
compile stralloc_eady.c alloc.h stralloc.h gen_alloc.h \
gen_allocdefs.h
	./compile stralloc_eady.c

stralloc_num.o: \
compile stralloc_num.c stralloc.h gen_alloc.h
	./compile stralloc_num.c

stralloc_opyb.o: \
compile stralloc_opyb.c stralloc.h gen_alloc.h byte.h
	./compile stralloc_opyb.c

stralloc_opys.o: \
compile stralloc_opys.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_opys.c

stralloc_pend.o: \
compile stralloc_pend.c alloc.h stralloc.h gen_alloc.h \
gen_allocdefs.h
	./compile stralloc_pend.c

strerr_die.o: \
compile strerr_die.c buffer.h exit.h strerr.h
	./compile strerr_die.c

strerr_sys.o: \
compile strerr_sys.c error.h strerr.h
	./compile strerr_sys.c

subgetopt.o: \
compile subgetopt.c subgetopt.h
	./compile subgetopt.c

systype: \
find-systype.sh conf-cc conf-ld trycpp.c x86cpuid.c
	( cat warn-auto.sh; \
	echo CC=\'`head -1 conf-cc`\'; \
	echo LD=\'`head -1 conf-ld`\'; \
	cat find-systype.sh; \
	) | sh > systype

tai_add.o: \
compile tai_add.c tai.h uint64.h
	./compile tai_add.c

tai_now.o: \
compile tai_now.c tai.h uint64.h
	./compile tai_now.c

tai_pack.o: \
compile tai_pack.c tai.h uint64.h
	./compile tai_pack.c

tai_sub.o: \
compile tai_sub.c tai.h uint64.h
	./compile tai_sub.c

tai_uint.o: \
compile tai_uint.c tai.h uint64.h
	./compile tai_uint.c

tai_unpack.o: \
compile tai_unpack.c tai.h uint64.h
	./compile tai_unpack.c

taia_add.o: \
compile taia_add.c taia.h tai.h uint64.h
	./compile taia_add.c

taia_approx.o: \
compile taia_approx.c taia.h tai.h uint64.h
	./compile taia_approx.c

taia_frac.o: \
compile taia_frac.c taia.h tai.h uint64.h
	./compile taia_frac.c

taia_less.o: \
compile taia_less.c taia.h tai.h uint64.h
	./compile taia_less.c

taia_now.o: \
compile taia_now.c taia.h tai.h uint64.h
	./compile taia_now.c

taia_pack.o: \
compile taia_pack.c taia.h tai.h uint64.h
	./compile taia_pack.c

taia_sub.o: \
compile taia_sub.c taia.h tai.h uint64.h
	./compile taia_sub.c

taia_tai.o: \
compile taia_tai.c taia.h tai.h uint64.h
	./compile taia_tai.c

taia_uint.o: \
compile taia_uint.c taia.h tai.h uint64.h
	./compile taia_uint.c

tdlookup.o: \
compile tdlookup.c uint16.h open.h tai.h uint64.h cdb.h uint32.h \
byte.h case.h dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h \
taia.h seek.h response.h uint32.h
	./compile tdlookup.c

timeoutread.o: \
compile timeoutread.c error.h iopause.h taia.h tai.h uint64.h \
timeoutread.h
	./compile timeoutread.c

timeoutwrite.o: \
compile timeoutwrite.c error.h iopause.h taia.h tai.h uint64.h \
timeoutwrite.h
	./compile timeoutwrite.c

tinydns: \
load tinydns.o server.o droproot.o tdlookup.o response.o qlog.o \
prot.o dns.a libtai.a env.a cdb.a alloc.a buffer.a unix.a byte.a \
socket.lib
	./load tinydns server.o droproot.o tdlookup.o response.o \
	qlog.o prot.o dns.a libtai.a env.a cdb.a alloc.a buffer.a \
	unix.a byte.a  `cat socket.lib`

tinydns-conf: \
load tinydns-conf.o generic-conf.o auto_home.o buffer.a unix.a byte.a
	./load tinydns-conf generic-conf.o auto_home.o buffer.a \
	unix.a byte.a 

tinydns-conf.o: \
compile tinydns-conf.c strerr.h exit.h auto_home.h generic-conf.h \
buffer.h
	./compile tinydns-conf.c

tinydns-data: \
load tinydns-data.o cdb.a dns.a alloc.a buffer.a unix.a byte.a
	./load tinydns-data cdb.a dns.a alloc.a buffer.a unix.a \
	byte.a 

tinydns-data.o: \
compile tinydns-data.c uint16.h uint32.h str.h byte.h fmt.h ip4.h \
exit.h case.h scan.h buffer.h strerr.h getln.h buffer.h stralloc.h \
gen_alloc.h cdb_make.h buffer.h uint32.h stralloc.h open.h dns.h \
stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile tinydns-data.c

tinydns-edit: \
load tinydns-edit.o dns.a alloc.a buffer.a unix.a byte.a
	./load tinydns-edit dns.a alloc.a buffer.a unix.a byte.a 

tinydns-edit.o: \
compile tinydns-edit.c stralloc.h gen_alloc.h buffer.h exit.h open.h \
getln.h buffer.h stralloc.h strerr.h scan.h byte.h str.h fmt.h ip4.h \
dns.h stralloc.h iopause.h taia.h tai.h uint64.h taia.h
	./compile tinydns-edit.c

tinydns-get: \
load tinydns-get.o tdlookup.o response.o printpacket.o printrecord.o \
parsetype.o dns.a libtai.a cdb.a buffer.a alloc.a unix.a byte.a
	./load tinydns-get tdlookup.o response.o printpacket.o \
	printrecord.o parsetype.o dns.a libtai.a cdb.a buffer.a \
	alloc.a unix.a byte.a 

tinydns-get.o: \
compile tinydns-get.c str.h byte.h scan.h exit.h stralloc.h \
gen_alloc.h buffer.h strerr.h uint16.h response.h uint32.h case.h \
printpacket.h stralloc.h parsetype.h ip4.h dns.h stralloc.h iopause.h \
taia.h tai.h uint64.h taia.h
	./compile tinydns-get.c

tinydns.o: \
compile tinydns.c dns.h stralloc.h gen_alloc.h iopause.h taia.h tai.h \
uint64.h taia.h
	./compile tinydns.c

uint16_pack.o: \
compile uint16_pack.c uint16.h
	./compile uint16_pack.c

uint16_unpack.o: \
compile uint16_unpack.c uint16.h
	./compile uint16_unpack.c

uint32.h: \
tryulong32.c compile load uint32.h1 uint32.h2
	( ( ./compile tryulong32.c && ./load tryulong32 && \
	./tryulong32 ) >/dev/null 2>&1 \
	&& cat uint32.h2 || cat uint32.h1 ) > uint32.h
	rm -f tryulong32.o tryulong32

uint32_pack.o: \
compile uint32_pack.c uint32.h
	./compile uint32_pack.c

uint32_unpack.o: \
compile uint32_unpack.c uint32.h
	./compile uint32_unpack.c

uint64.h: \
choose compile load tryulong64.c uint64.h1 uint64.h2
	./choose clr tryulong64 uint64.h1 uint64.h2 > uint64.h

unix.a: \
makelib buffer_read.o buffer_write.o error.o error_str.o ndelay_off.o \
ndelay_on.o open_read.o open_trunc.o openreadclose.o readclose.o \
seek_set.o socket_accept.o socket_bind.o socket_conn.o \
socket_listen.o socket_recv.o socket_send.o socket_tcp.o socket_udp.o
	./makelib unix.a buffer_read.o buffer_write.o error.o \
	error_str.o ndelay_off.o ndelay_on.o open_read.o \
	open_trunc.o openreadclose.o readclose.o seek_set.o \
	socket_accept.o socket_bind.o socket_conn.o socket_listen.o \
	socket_recv.o socket_send.o socket_tcp.o socket_udp.o

utime: \
load utime.o byte.a
	./load utime byte.a 

utime.o: \
compile utime.c scan.h exit.h
	./compile utime.c

walldns: \
load walldns.o server.o response.o droproot.o qlog.o prot.o dd.o \
dns.a env.a cdb.a alloc.a buffer.a unix.a byte.a socket.lib
	./load walldns server.o response.o droproot.o qlog.o \
	prot.o dd.o dns.a env.a cdb.a alloc.a buffer.a unix.a \
	byte.a  `cat socket.lib`

walldns-conf: \
load walldns-conf.o generic-conf.o auto_home.o buffer.a unix.a byte.a
	./load walldns-conf generic-conf.o auto_home.o buffer.a \
	unix.a byte.a 

walldns-conf.o: \
compile walldns-conf.c strerr.h exit.h auto_home.h generic-conf.h \
buffer.h
	./compile walldns-conf.c

walldns.o: \
compile walldns.c byte.h dns.h stralloc.h gen_alloc.h iopause.h \
taia.h tai.h uint64.h taia.h dd.h response.h uint32.h
	./compile walldns.c
