#include "dns.h"
#include "dd.h"

int dd(const char *q,const char *base,char ip[4])
{
  int j;
  unsigned int x;

  for (j = 0;;++j) {
    if (dns_domain_equal(q,base)) return j;
    if (j >= 4) return -1;

    if (*q <= 0) return -1;
    if (*q >= 4) return -1;
    if ((q[1] < '0') || (q[1] > '9')) return -1;
    x = q[1] - '0';
    if (*q == 1) {
      ip[j] = x;
      q += 2;
      continue;
    }
    if (!x) return -1;
    if ((q[2] < '0') || (q[2] > '9')) return -1;
    x = x * 10 + (q[2] - '0');
    if (*q == 2) {
      ip[j] = x;
      q += 3;
      continue;
    }
    if ((q[3] < '0') || (q[3] > '9')) return -1;
    x = x * 10 + (q[3] - '0');
    if (x > 255) return -1;
    ip[j] = x;
    q += 4;
  }
}
