#include "buffer.h"
#include "exit.h"
#include "fmt.h"
#include "scan.h"
#include "dns.h"

char ip[4];
int ipfixed = 0;
unsigned long loops = 10000;
unsigned char tab[256];

char strnum[FMT_ULONG];

char seed[128];

int main(int argc,char **argv)
{
  unsigned long u;
  int i;
  int j;
  unsigned char c;

  dns_random_init(seed);

  for (i = 0;i < 256;++i) tab[i] = i;
  for (j = 256;j > 0;--j) {
    i = dns_random(j);
    c = tab[j - 1];
    tab[j - 1] = tab[i];
    tab[i] = c;
  }

  if (*argv) ++argv;
  if (*argv) scan_ulong(*argv++,&loops);
  if (*argv) { scan_ulong(*argv++,&u); ip[0] = u; ipfixed = 1; }
  if (*argv) { scan_ulong(*argv++,&u); ip[1] = u; ipfixed = 2; }
  if (*argv) { scan_ulong(*argv++,&u); ip[2] = u; ipfixed = 3; }
  if (*argv) { scan_ulong(*argv++,&u); ip[3] = u; ipfixed = 4; }

  if (ipfixed >= 1) if (loops > 16777216) loops = 16777216;
  if (ipfixed >= 2) if (loops > 65536) loops = 65536;
  if (ipfixed >= 3) if (loops > 256) loops = 256;
  if (ipfixed >= 4) if (loops > 1) loops = 1;

  while (loops) {
    --loops;
    u = loops;
    for (i = ipfixed;i < 4;++i) { ip[i] = u & 255; u >>= 8; }
    if (ipfixed == 3) {
      c = ip[3];
      ip[3] = tab[c];
    }
    else if (ipfixed < 3) {
      c = 0;
      for (j = 0;j < 100;++j) {
        for (i = ipfixed;i < 4;++i) {
          c ^= (unsigned char) ip[i];
          c = tab[c];
          ip[i] = c;
        }
      }
    }

    u = (unsigned char) ip[0];
    buffer_put(buffer_1,strnum,fmt_ulong(strnum,u));
    buffer_puts(buffer_1,".");
    u = (unsigned char) ip[1];
    buffer_put(buffer_1,strnum,fmt_ulong(strnum,u));
    buffer_puts(buffer_1,".");
    u = (unsigned char) ip[2];
    buffer_put(buffer_1,strnum,fmt_ulong(strnum,u));
    buffer_puts(buffer_1,".");
    u = (unsigned char) ip[3];
    buffer_put(buffer_1,strnum,fmt_ulong(strnum,u));
    buffer_puts(buffer_1,"\n");
  }

  buffer_flush(buffer_1);
  _exit(0);
}
