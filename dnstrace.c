#include "uint16.h"
#include "uint32.h"
#include "fmt.h"
#include "str.h"
#include "byte.h"
#include "ip4.h"
#include "gen_alloc.h"
#include "gen_allocdefs.h"
#include "exit.h"
#include "buffer.h"
#include "stralloc.h"
#include "error.h"
#include "strerr.h"
#include "iopause.h"
#include "printrecord.h"
#include "parsetype.h"
#include "dns.h"

#define FATAL "dnstrace: fatal: "
#define ALERT "\tA\10AL\10LE\10ER\10RT\10T:\10: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}
void usage(void)
{
  strerr_die1x(100,"dnstrace: usage: dnstrace type name rootip ...");
}

char ipstr[IP4_FMT];
char strnum[FMT_ULONG];
static stralloc tmp;

void printtype(char type[2])
{
  uint16 u16;
  uint16_unpack_big(type,&u16);
  buffer_put(buffer_1,strnum,fmt_ulong(strnum,u16));
}
void printdomain(char *d)
{
  if (!stralloc_copys(&tmp,"")) nomem();
  if (!dns_domain_todot_cat(&tmp,d)) nomem();
  buffer_put(buffer_1,tmp.s,tmp.len);
}
void printcontrol(char *d)
{
  int i;
  if (!stralloc_copys(&tmp,"")) nomem();
  if (!dns_domain_todot_cat(&tmp,d)) nomem();
  for (i = 0;i < tmp.len;++i) {
    buffer_put(buffer_1,"_\10",2);
    buffer_put(buffer_1,tmp.s + i,1);
  }
}

static struct dns_transmit tx;

int resolve(char *q,char qtype[2],char ip[4])
{
  struct taia start;
  struct taia stamp;
  struct taia deadline;
  char servers[64];
  iopause_fd x[1];
  int r;

  taia_now(&start);

  byte_zero(servers,64);
  byte_copy(servers,4,ip);

  if (dns_transmit_start(&tx,servers,0,q,qtype,"\0\0\0\0") == -1) return -1;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);
    dns_transmit_io(&tx,x,&deadline);
    iopause(x,1,&deadline,&stamp);
    r = dns_transmit_get(&tx,x,&stamp);
    if (r == -1) return -1;
    if (r == 1) break;
  }

  taia_now(&stamp);
  taia_sub(&stamp,&stamp,&start);
  taia_uint(&deadline,1);
  if (taia_less(&deadline,&stamp)) {
    buffer_puts(buffer_1,ALERT);
    buffer_puts(buffer_1,"resolution took more than 1 second\n");
  }

  return 0;
}

struct address {
  char *owner;
  char ip[4];
} ;

GEN_ALLOC_typedef(address_alloc,struct address,s,len,a)
GEN_ALLOC_readyplus(address_alloc,struct address,s,len,a,i,n,x,30,address_alloc_readyplus)
GEN_ALLOC_append(address_alloc,struct address,s,len,a,i,n,x,30,address_alloc_readyplus,address_alloc_append)

static address_alloc address;

struct ns {
  char *owner;
  char *ns;
} ;

GEN_ALLOC_typedef(ns_alloc,struct ns,s,len,a)
GEN_ALLOC_readyplus(ns_alloc,struct ns,s,len,a,i,n,x,30,ns_alloc_readyplus)
GEN_ALLOC_append(ns_alloc,struct ns,s,len,a,i,n,x,30,ns_alloc_readyplus,ns_alloc_append)

static ns_alloc ns;

struct query {
  char *owner;
  char type[2];
} ;

GEN_ALLOC_typedef(query_alloc,struct query,s,len,a)
GEN_ALLOC_readyplus(query_alloc,struct query,s,len,a,i,n,x,30,query_alloc_readyplus)
GEN_ALLOC_append(query_alloc,struct query,s,len,a,i,n,x,30,query_alloc_readyplus,query_alloc_append)

static query_alloc query;

struct qt {
  char *owner;
  char type[2];
  char *control;
  char ip[4];
} ;

GEN_ALLOC_typedef(qt_alloc,struct qt,s,len,a)
GEN_ALLOC_readyplus(qt_alloc,struct qt,s,len,a,i,n,x,30,qt_alloc_readyplus)
GEN_ALLOC_append(qt_alloc,struct qt,s,len,a,i,n,x,30,qt_alloc_readyplus,qt_alloc_append)

static qt_alloc qt;

void qt_add(char *q,char type[2],char *control,char ip[4])
{
  struct qt x;
  int i;

  if (!*q) return; /* don't ask the roots about our artificial . host */

  for (i = 0;i < qt.len;++i)
    if (dns_domain_equal(qt.s[i].owner,q))
      if (dns_domain_equal(qt.s[i].control,control))
        if (byte_equal(qt.s[i].type,2,type))
	  if (byte_equal(qt.s[i].ip,4,ip))
	    return;

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,q)) nomem();
  if (!dns_domain_copy(&x.control,control)) nomem();
  byte_copy(x.type,2,type);
  byte_copy(x.ip,4,ip);
  if (!qt_alloc_append(&qt,&x)) nomem();
}

void query_add(char *owner,char type[2])
{
  struct query x;
  int i;
  int j;

  for (i = 0;i < query.len;++i)
    if (dns_domain_equal(query.s[i].owner,owner))
      if (byte_equal(query.s[i].type,2,type))
	return;

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,owner)) nomem();
  byte_copy(x.type,2,type);
  if (!query_alloc_append(&query,&x)) nomem();
  
  for (i = 0;i < ns.len;++i)
    if (dns_domain_suffix(owner,ns.s[i].owner))
      for (j = 0;j < address.len;++j)
	if (dns_domain_equal(ns.s[i].ns,address.s[j].owner))
	  qt_add(owner,type,ns.s[i].owner,address.s[j].ip);
}

void ns_add(char *owner,char *server)
{
  struct ns x;
  int i;
  int j;

  for (i = 0;i < ns.len;++i)
    if (dns_domain_equal(ns.s[i].owner,owner))
      if (dns_domain_equal(ns.s[i].ns,server))
	return;

  query_add(server,DNS_T_A);

  buffer_puts(buffer_1,"\t\t\t\t");
  printdomain(owner);
  buffer_puts(buffer_1," cache NS ");
  printdomain(server);
  buffer_puts(buffer_1,"\n");

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,owner)) nomem();
  if (!dns_domain_copy(&x.ns,server)) nomem();
  if (!ns_alloc_append(&ns,&x)) nomem();

  for (i = 0;i < query.len;++i)
    if (dns_domain_suffix(query.s[i].owner,owner))
      for (j = 0;j < address.len;++j)
	if (dns_domain_equal(server,address.s[j].owner))
	  qt_add(query.s[i].owner,query.s[i].type,owner,address.s[j].ip);
}

void address_add(char *owner,char ip[4])
{
  struct address x;
  int i;
  int j;

  for (i = 0;i < address.len;++i)
    if (dns_domain_equal(address.s[i].owner,owner))
      if (byte_equal(address.s[i].ip,4,ip))
	return;

  buffer_puts(buffer_1,"\t\t\t\t");
  printdomain(owner);
  buffer_puts(buffer_1," cache A ");
  buffer_put(buffer_1,ipstr,ip4_fmt(ipstr,ip));
  buffer_puts(buffer_1,"\n");

  byte_zero(&x,sizeof x);
  if (!dns_domain_copy(&x.owner,owner)) nomem();
  byte_copy(x.ip,4,ip);
  if (!address_alloc_append(&address,&x)) nomem();

  for (i = 0;i < ns.len;++i)
    if (dns_domain_equal(ns.s[i].ns,owner))
      for (j = 0;j < query.len;++j)
	if (dns_domain_suffix(query.s[j].owner,ns.s[i].owner))
	  qt_add(query.s[j].owner,query.s[j].type,ns.s[i].owner,ip);
}

char seed[128];

static char *t1;
static char *t2;
static char *referral;
static char *cname;

static int typematch(char rtype[2],char qtype[2])
{
  return byte_equal(qtype,2,rtype) || byte_equal(qtype,2,DNS_T_ANY);
}

void parsepacket(char *buf,unsigned int len,char *d,char dtype[2],char *control)
{
  char misc[20];
  char header[12];
  unsigned int pos;
  unsigned int pos2;
  uint16 numanswers;
  unsigned int posanswers;
  uint16 numauthority;
  unsigned int posauthority;
  uint16 numglue;
  unsigned int posglue;
  uint16 datalen;
  unsigned int rcode;
  int flagout;
  int flagcname;
  int flagreferral;
  int flagsoa;
  int i;
  int j;
  char *x;

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) goto DIE;
  pos = dns_packet_skipname(buf,len,pos); if (!pos) goto DIE;
  pos += 4;

  uint16_unpack_big(header + 6,&numanswers);
  uint16_unpack_big(header + 8,&numauthority);
  uint16_unpack_big(header + 10,&numglue);

  rcode = header[3] & 15;
  if (rcode && (rcode != 3)) { errno = error_proto; goto DIE; } /* impossible */

  flagout = 0;
  flagcname = 0;
  flagreferral = 0;
  flagsoa = 0;
  posanswers = pos;
  for (j = 0;j < numanswers;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    if (dns_domain_equal(t1,d))
      if (byte_equal(header + 2,2,DNS_C_IN))
	if (typematch(header,dtype))
	  flagout = 1;
	else if (typematch(header,DNS_T_CNAME)) {
          if (!dns_packet_getname(buf,len,pos,&cname)) goto DIE;
          flagcname = 1;
	}
    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }
  posauthority = pos;
  for (j = 0;j < numauthority;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    if (typematch(header,DNS_T_SOA))
      flagsoa = 1;
    else if (typematch(header,DNS_T_NS)) {
      flagreferral = 1;
      if (!dns_domain_copy(&referral,t1)) goto DIE;
    }
    uint16_unpack_big(header + 8,&datalen);
    pos += datalen;
  }
  posglue = pos;

  if (!flagcname && !rcode && !flagout && flagreferral && !flagsoa)
    if (dns_domain_equal(referral,control) || !dns_domain_suffix(referral,control)) {
      buffer_puts(buffer_1,ALERT);
      buffer_puts(buffer_1,"lame server; refers to ");
      printdomain(referral);
      buffer_puts(buffer_1,"\n");
      return;
    }

  pos = posanswers;
  for (j = 0;j < numanswers + numauthority + numglue;++j) {
    pos = dns_packet_getname(buf,len,pos,&t1); if (!pos) goto DIE;
    pos = dns_packet_copy(buf,len,pos,header,10); if (!pos) goto DIE;
    uint16_unpack_big(header + 8,&datalen);
    if (dns_domain_suffix(t1,control))
      if (byte_equal(header + 2,2,DNS_C_IN)) {
        if (typematch(header,DNS_T_NS)) {
	  if (!dns_packet_getname(buf,len,pos,&t2)) goto DIE;
	  ns_add(t1,t2);
        }
        else if (typematch(header,DNS_T_A) && datalen == 4) {
	  if (!dns_packet_copy(buf,len,pos,misc,4)) goto DIE;
	  address_add(t1,misc);
        }
      }
    pos += datalen;
  }


  if (flagcname) {
    query_add(cname,dtype);
    buffer_puts(buffer_1,"\t\t\t\tCNAME ");
    printdomain(cname);
    buffer_puts(buffer_1,"\n");
    return;
  }
  if (rcode == 3) {
    buffer_puts(buffer_1,"\t\t\t\tNXDOMAIN\n");
    return;
  }
  if (flagout || flagsoa || !flagreferral) {
    if (!flagout) {
      buffer_puts(buffer_1,"\t\t\t\tNODATA\n");
      return;
    }
    pos = posanswers;
    for (j = 0;j < numanswers + numauthority + numglue;++j) {
      pos = printrecord(&tmp,buf,len,pos,d,dtype);
      if (!pos) goto DIE;
      if (tmp.len) {
        buffer_puts(buffer_1,"\t\t\t\t");
        buffer_put(buffer_1,tmp.s,tmp.len);
      }
    }
    return;
  }

  if (!dns_domain_suffix(d,referral)) goto DIE;
  buffer_puts(buffer_1,"\t\t\t\tsee ");
  printdomain(referral);
  buffer_puts(buffer_1,"\n");
  return;

  DIE:
  x = error_str(errno);
  buffer_puts(buffer_1,ALERT);
  buffer_puts(buffer_1,"unable to parse response packet: ");
  buffer_puts(buffer_1,x);
}

main(int argc,char **argv)
{
  static stralloc out;
  static stralloc fqdn;
  static stralloc udn;
  static char *q;
  char *control;
  char type[2];
  char ip[64];
  int r;
  int i;
  char ch;

  dns_random_init(seed);

  if (!address_alloc_readyplus(&address,1)) nomem();
  if (!query_alloc_readyplus(&query,1)) nomem();
  if (!ns_alloc_readyplus(&ns,1)) nomem();
  if (!qt_alloc_readyplus(&qt,1)) nomem();

  if (!*argv) usage();
  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (!dns_domain_fromdot(&q,*argv,str_len(*argv))) nomem();

  query_add(q,type);
  ns_add("","");

  while (*++argv) {
    if (!stralloc_copys(&udn,*argv)) nomem();
    if (dns_ip4_qualify(&out,&fqdn,&udn) == -1) nomem(); /* XXX */
    for (i = 0;i + 4 <= out.len;i += 4)
      address_add("",out.s + i);
  }

  for (i = 0;i < qt.len;++i) {
    if (!dns_domain_copy(&q,qt.s[i].owner)) nomem();
    control = dns_domain_suffix(q,qt.s[i].control);
    if (!control) continue;
    byte_copy(type,2,qt.s[i].type);
    byte_copy(ip,4,qt.s[i].ip);

    printtype(type);
    buffer_puts(buffer_1," ");
    if (control == q)
      printcontrol(control);
    else {
      ch = *control;
      *control = 0;
      printdomain(q);
      if (ch) {
        *control = ch;
        buffer_puts(buffer_1,".");
        printcontrol(control);
      }
    }
    buffer_puts(buffer_1," ");
    buffer_put(buffer_1,ipstr,ip4_fmt(ipstr,ip));
    buffer_puts(buffer_1,"\n");
    buffer_flush(buffer_1);

    if (resolve(q,type,ip) == -1) {
      char *x = error_str(errno);
      buffer_puts(buffer_1,ALERT);
      buffer_puts(buffer_1,x);
      buffer_puts(buffer_1,"\n");
    }
    else
      parsepacket(tx.packet,tx.packetlen,q,type,control);
    buffer_flush(buffer_1);
  }

  _exit(0);
}
