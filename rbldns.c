#include <unistd.h>
#include "str.h"
#include "byte.h"
#include "ip4.h"
#include "open.h"
#include "env.h"
#include "cdb.h"
#include "dns.h"
#include "dd.h"
#include "strerr.h"
#include "response.h"

static char *base;

static struct cdb c;
static char key[5];
static char data[100 + IP4_FMT];

static int doit(char *q,char qtype[2])
{
  int flaga;
  int flagtxt;
  char ch;
  char reverseip[4];
  char ip[4];
  uint32 ipnum;
  int r;
  uint32 dlen;
  int i;

  flaga = byte_equal(qtype,2,DNS_T_A);
  flagtxt = byte_equal(qtype,2,DNS_T_TXT);
  if (byte_equal(qtype,2,DNS_T_ANY)) flaga = flagtxt = 1;
  if (!flaga && !flagtxt) goto REFUSE;

  if (dd(q,base,reverseip) != 4) goto REFUSE;
  uint32_unpack(reverseip,&ipnum);
  uint32_pack_big(ip,ipnum);

  for (i = 0;i <= 24;++i) {
    ipnum >>= i;
    ipnum <<= i;
    uint32_pack_big(key,ipnum);
    key[4] = 32 - i;
    r = cdb_find(&c,key,5);
    if (r == -1) return 0;
    if (r) break;
  }
  if (!r) { response_nxdomain(); return 1; }

  r = cdb_find(&c,"",0);
  if (r == -1) return 0;
  if (r && ((dlen = cdb_datalen(&c)) >= 4)) {
    if (dlen > 100) dlen = 100;
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return 0;
  }
  else {
    dlen = 12;
    byte_copy(data,dlen,"\177\0\0\2Listed $");
  }

  if ((dlen >= 5) && (data[dlen - 1] == '$')) {
    --dlen;
    dlen += ip4_fmt(data + dlen,ip);
  }

  if (flaga) {
    if (!response_rstart(q,DNS_T_A,2048)) return 0;
    if (!response_addbytes(data,4)) return 0;
    response_rfinish(RESPONSE_ANSWER);
  }
  if (flagtxt) {
    if (!response_rstart(q,DNS_T_TXT,2048)) return 0;
    ch = dlen - 4;
    if (!response_addbytes(&ch,1)) return 0;
    if (!response_addbytes(data + 4,dlen - 4)) return 0;
    response_rfinish(RESPONSE_ANSWER);
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
  result = doit(q,qtype);
  cdb_free(&c);
  close(fd);
  return result;
}

const char *fatal = "rbldns: fatal: ";
const char *starting = "starting rbldns\n";

void initialize(void)
{
  char *x;

  x = env_get("BASE");
  if (!x)
    strerr_die2x(111,fatal,"$BASE not set");
  if (!dns_domain_fromdot(&base,x,str_len(x)))
    strerr_die2x(111,fatal,"unable to parse $BASE");
}
