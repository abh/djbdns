#include "dns.h"
#include "byte.h"
#include "uint16.h"
#include "response.h"

char response[65535];
unsigned int response_len = 0; /* <= 65535 */
static unsigned int tctarget;

#define NAMES 100
static char name[NAMES][128];
static unsigned int name_ptr[NAMES]; /* each < 16384 */
static unsigned int name_num;

int response_addbytes(char *buf,unsigned int len)
{
  if (len > 65535 - response_len) return 0;
  byte_copy(response + response_len,len,buf);
  response_len += len;
  return 1;
}

int response_addname(char *d)
{
  unsigned int dlen;
  unsigned int i;
  char buf[2];

  dlen = dns_domain_length(d);

  while (*d) {
    for (i = 0;i < name_num;++i)
      if (dns_domain_equal(d,name[i])) {
        uint16_pack_big(buf,49152 + name_ptr[i]);
        return response_addbytes(buf,2);
      }
    if (dlen <= 128)
      if (name_num < NAMES) {
	byte_copy(name[name_num],dlen,d);
	name_ptr[name_num] = response_len;
	++name_num;
      }
    i = (unsigned char) *d;
    ++i;
    if (!response_addbytes(d,i)) return 0;
    d += i;
    dlen -= i;
  }
  return response_addbytes(d,1);
}

int response_query(char *q,char qtype[2])
{
  response_len = 0;
  name_num = 0;
  if (!response_addbytes("\0\0\201\200\0\1\0\0\0\0\0\0",12)) return 0;
  if (!response_addname(q)) return 0;
  if (!response_addbytes(qtype,2)) return 0;
  if (!response_addbytes(DNS_C_IN,2)) return 0;
  tctarget = response_len;
  return 1;
}

static unsigned int dpos;

int response_rstart(char *d,char type[2],char ttl[4])
{
  if (!response_addname(d)) return 0;
  if (!response_addbytes(type,2)) return 0;
  if (!response_addbytes(DNS_C_IN,2)) return 0;
  if (!response_addbytes(ttl,4)) return 0;
  if (!response_addbytes("\0\0",2)) return 0;
  dpos = response_len;
  return 1;
}

void response_rfinish(int x)
{
  uint16_pack_big(response + dpos - 2,response_len - dpos);
  if (!++response[x + 1]) ++response[x];
}

int response_cname(char *c,char *d)
{
  if (!response_rstart(c,DNS_T_CNAME,"\0\0\0\0")) return 0;
  if (!response_addname(d)) return 0;
  response_rfinish(RESPONSE_ANSWER);
  return 1;
}

void response_nxdomain(void)
{
  response[3] |= 3;
  response[2] |= 4;
}

void response_servfail(void)
{
  response[3] |= 2;
}

void response_id(char id[2])
{
  byte_copy(response,2,id);
}

void response_tc(void)
{
  response[2] |= 2;
  response_len = tctarget;
}
