#include "uint16.h"
#include "strerr.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "byte.h"
#include "error.h"
#include "iopause.h"
#include "printpacket.h"
#include "parsetype.h"
#include "dns.h"

#define FATAL "dnsqr: fatal: "

void usage(void)
{
  strerr_die1x(100,"dnsqr: usage: dnsqr type name");
}
void oops(void)
{
  strerr_die2sys(111,FATAL,"unable to parse: ");
}

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

  if (*++argv) usage();

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (!dns_domain_todot_cat(&out,q)) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (dns_resolve(q,type) == -1) {
    if (!stralloc_cats(&out,error_str(errno))) oops();
    if (!stralloc_cats(&out,"\n")) oops();
  }
  else {
    if (dns_resolve_tx.packetlen < 4) oops();
    dns_resolve_tx.packet[2] &= ~1;
    dns_resolve_tx.packet[3] &= ~128;
    if (!printpacket_cat(&out,dns_resolve_tx.packet,dns_resolve_tx.packetlen)) oops();
  }

  buffer_putflush(buffer_1,out.s,out.len);
  _exit(0);
}
