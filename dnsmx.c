#include "buffer.h"
#include "exit.h"
#include "strerr.h"
#include "uint16.h"
#include "byte.h"
#include "fmt.h"
#include "dns.h"

#define FATAL "dnsmx: fatal: "

static char seed[128];

static stralloc fqdn;
static stralloc out;
char strnum[FMT_ULONG];

main(int argc,char **argv)
{
  int i;
  int j;
  uint16 pref;

  dns_random_init(seed);

  if (*argv) ++argv;

  while (*argv) {
    if (!stralloc_copys(&fqdn,*argv))
      strerr_die2x(111,FATAL,"out of memory");
    if (dns_mx(&out,&fqdn) == -1)
      strerr_die4sys(111,FATAL,"unable to find MX records for ",*argv,": ");

    if (!out.len) {
      buffer_puts(buffer_1,"0 ");
      buffer_puts(buffer_1,*argv);
      buffer_puts(buffer_1,"\n");
    }
    else {
      i = 0;
      while (i + 2 < out.len) {
	j = byte_chr(out.s + i + 2,out.len - i - 2,0);
	uint16_unpack_big(out.s + i,&pref);
	buffer_put(buffer_1,strnum,fmt_ulong(strnum,pref));
	buffer_puts(buffer_1," ");
	buffer_put(buffer_1,out.s + i + 2,j);
	buffer_puts(buffer_1,"\n");
	i += j + 3;
      }
    }

    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
