#include <unistd.h>
#include "byte.h"
#include "case.h"
#include "dns.h"
#include "open.h"
#include "cdb.h"
#include "response.h"

const char *fatal = "pickdns: fatal: ";
const char *starting = "starting pickdns\n";

static char seed[128];

void initialize(void)
{
  dns_random_init(seed);
}

static struct cdb c;
static char key[258];
static char data[512];

static int doit(char *q,char qtype[2],char ip[4])
{
  int r;
  uint32 dlen;
  unsigned int qlen;
  int flaga;
  int flagmx;

  qlen = dns_domain_length(q);
  if (qlen > 255) return 0; /* impossible */

  flaga = byte_equal(qtype,2,DNS_T_A);
  flagmx = byte_equal(qtype,2,DNS_T_MX);
  if (byte_equal(qtype,2,DNS_T_ANY)) flaga = flagmx = 1;
  if (!flaga && !flagmx) goto REFUSE;

  key[0] = '%';
  byte_copy(key + 1,4,ip);

  r = cdb_find(&c,key,5);
  if (!r) r = cdb_find(&c,key,4);
  if (!r) r = cdb_find(&c,key,3);
  if (!r) r = cdb_find(&c,key,2);
  if (r == -1) return 0;

  key[0] = '+';
  byte_zero(key + 1,2);
  if (r && (cdb_datalen(&c) == 2))
    if (cdb_read(&c,key + 1,2,cdb_datapos(&c)) == -1) return 0;

  byte_copy(key + 3,qlen,q);
  case_lowerb(key + 3,qlen + 3);

  r = cdb_find(&c,key,qlen + 3);
  if (!r) {
    byte_zero(key + 1,2);
    r = cdb_find(&c,key,qlen + 3);
  }
  if (!r) goto REFUSE;
  if (r == -1) return 0;
  dlen = cdb_datalen(&c);

  if (dlen > 512) dlen = 512;
  if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return 0;

  if (flaga) {
    dns_sortip(data,dlen);
    if (dlen > 12) dlen = 12;
    while (dlen >= 4) {
      dlen -= 4;
      if (!response_rstart(q,DNS_T_A,5)) return 0;
      if (!response_addbytes(data + dlen,4)) return 0;
      response_rfinish(RESPONSE_ANSWER);
    }
  }

  return 1;


  REFUSE:
  response[2] &= ~4;
  response[3] &= ~15;
  response[3] |= 5;
  return 1;
}

int respond(char *q,char qtype[2],char ip[4])
{
  int fd;
  int result;

  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);
  result = doit(q,qtype,ip);
  cdb_free(&c);
  close(fd);
  return result;
}
