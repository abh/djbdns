#include "uint16.h"
#include "strerr.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "byte.h"
#include "error.h"
#include "ip4.h"
#include "iopause.h"
#include "printpacket.h"
#include "parsetype.h"
#include "dns.h"

#define FATAL "dnsq: fatal: "

void usage(void)
{
  strerr_die1x(100,"dnsq: usage: dnsq type name server");
}
void oops(void)
{
  strerr_die2sys(111,FATAL,"unable to parse: ");
}

static struct dns_transmit tx;

int resolve(char *q,char qtype[2],char servers[64])
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

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

  return 0;
}

char servers[64];
static stralloc ip;
static stralloc fqdn;

char type[2];
static char *q;

static stralloc out;

static char seed[128];

int main(int argc,char **argv)
{
  uint16 u16;

  dns_random_init(seed);

  if (!*argv) usage();
  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (!dns_domain_fromdot(&q,*argv,str_len(*argv))) oops();

  if (!*++argv) usage();
  if (!stralloc_copys(&out,*argv)) oops();
  if (dns_ip4_qualify(&ip,&fqdn,&out) == -1) oops();
  if (ip.len >= 64) ip.len = 64;
  byte_zero(servers,64);
  byte_copy(servers,ip.len,ip.s);

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (!dns_domain_todot_cat(&out,q)) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (resolve(q,type,servers) == -1) {
    if (!stralloc_cats(&out,error_str(errno))) oops();
    if (!stralloc_cats(&out,"\n")) oops();
  }
  else {
    if (!printpacket_cat(&out,tx.packet,tx.packetlen)) oops();
  }

  buffer_putflush(buffer_1,out.s,out.len);
  _exit(0);
}
