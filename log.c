#include "buffer.h"
#include "uint32.h"
#include "uint16.h"
#include "error.h"
#include "byte.h"
#include "log.h"

/* work around gcc 2.95.2 bug */
#define number(x) ( (u64 = (x)), u64_print() )
static uint64 u64;
static void u64_print(void)
{
  char buf[20];
  unsigned int pos;

  pos = sizeof buf;
  do {
    if (!pos) break;
    buf[--pos] = '0' + (u64 % 10);
    u64 /= 10;
  } while(u64);

  buffer_put(buffer_2,buf + pos,sizeof buf - pos);
}

static void hex(unsigned char c)
{
  buffer_put(buffer_2,"0123456789abcdef" + (c >> 4),1);
  buffer_put(buffer_2,"0123456789abcdef" + (c & 15),1);
}

static void string(char *s)
{
  buffer_puts(buffer_2,s);
}

static void line(void)
{
  string("\n");
  buffer_flush(buffer_2);
}

static void space(void)
{
  string(" ");
}

static void ip(char ip[4])
{
  hex(ip[0]);
  hex(ip[1]);
  hex(ip[2]);
  hex(ip[3]);
}

static void logid(char id[2])
{
  hex(id[0]);
  hex(id[1]);
}

static void logtype(char type[2])
{
  uint16 u;

  uint16_unpack_big(type,&u);
  number(u);
}

static void name(char *q)
{
  char ch;
  int state;

  if (!*q) {
    string(".");
    return;
  }
  while (state = *q++) {
    while (state) {
      ch = *q++;
      --state;
      if ((ch <= 32) || (ch > 126)) ch = '?';
      if ((ch >= 'A') && (ch <= 'Z')) ch += 32;
      buffer_put(buffer_2,&ch,1);
    }
    string(".");
  }
}

void log_startup(void)
{
  string("starting");
  line();
}

void log_query(unsigned int qnum,char client[4],unsigned int port,char id[2],char *q,char qtype[2])
{
  string("query "); number(qnum); space();
  ip(client); string(":"); hex(port >> 8); hex(port & 255);
  string(":"); logid(id); space();
  logtype(qtype); space(); name(q);
  line();
}

void log_querydone(unsigned int qnum,unsigned int len)
{
  string("sent "); number(qnum); space();
  number(len);
  line();
}

void log_querydrop(unsigned int qnum)
{
  char *x = error_str(errno);

  string("drop "); number(qnum); space();
  string(x);
  line();
}

void log_conn(unsigned int qnum,char client[4],unsigned int port)
{
  string("connection "); number(qnum); space();
  ip(client); string(":"); hex(port >> 8); hex(port & 255);
  line();
}

void log_conndrop(unsigned int qnum)
{
  char *x = error_str(errno);

  string("dropconnection "); number(qnum); space();
  string(x);
  line();
}

void log_tx(char *q,char qtype[2],char *control,char servers[64],unsigned int gluelessness)
{
  int i;

  string("tx "); number(gluelessness); space();
  logtype(qtype); space(); name(q); space();
  name(control);
  for (i = 0;i < 64;i += 4)
    if (byte_diff(servers + i,4,"\0\0\0\0")) {
      space();
      ip(servers + i);
    }
  line();
}

void log_cachedanswer(char *q,char type[2])
{
  string("cached "); logtype(type); space();
  name(q);
  line();
}

void log_cachedcname(char *dn,char *dn2)
{
  string("cached cname "); name(dn); space(); name(dn2);
  line();
}

void log_cachedns(char *control,char *ns)
{
  string("cached ns "); name(control); space(); name(ns);
  line();
}

void log_cachednxdomain(char *dn)
{
  string("cached nxdomain "); name(dn);
  line();
}

void log_cachedservfail(char *dn)
{
  string("cached servfail "); name(dn);
  line();
}

void log_nxdomain(char server[4],char *q,unsigned int ttl)
{
  string("nxdomain "); ip(server); space(); number(ttl); space();
  name(q);
  line();
}

void log_nodata(char server[4],char *q,char qtype[2],unsigned int ttl)
{
  string("nodata "); ip(server); space(); number(ttl); space();
  logtype(qtype); space(); name(q);
  line();
}

void log_lame(char server[4],char *control,char *referral)
{
  string("lame "); ip(server); space();
  name(control); space(); name(referral);
  line();
}

void log_servfail(char *dn)
{
  char *x = error_str(errno);

  string("servfail "); name(dn); space();
  string(x);
  line();
}

void log_rr(char server[4],char *q,char type[2],char *buf,unsigned int len,unsigned int ttl)
{
  int i;

  string("rr "); ip(server); space(); number(ttl); space();
  logtype(type); space(); name(q); space();

  for (i = 0;i < len;++i) {
    hex(buf[i]);
    if (i > 30) {
      string("...");
      break;
    }
  }
  line();
}

void log_rrns(char server[4],char *q,char *data,unsigned int ttl)
{
  string("rr "); ip(server); space(); number(ttl);
  string(" ns "); name(q); space();
  name(data);
  line();
}

void log_rrcname(char server[4],char *q,char *data,unsigned int ttl)
{
  string("rr "); ip(server); space(); number(ttl);
  string(" cname "); name(q); space();
  name(data);
  line();
}

void log_rrptr(char server[4],char *q,char *data,unsigned int ttl)
{
  string("rr "); ip(server); space(); number(ttl);
  string(" ptr "); name(q); space();
  name(data);
  line();
}

void log_rrmx(char server[4],char *q,char *mx,char pref[2],unsigned int ttl)
{
  uint16 u;

  string("rr "); ip(server); space(); number(ttl);
  string(" mx "); name(q); space();
  uint16_unpack_big(pref,&u);
  number(u); space(); name(mx);
  line();
}

void log_rrsoa(char server[4],char *q,char *n1,char *n2,char misc[20],unsigned int ttl)
{
  uint32 u;
  int i;

  string("rr "); ip(server); space(); number(ttl);
  string(" soa "); name(q); space();
  name(n1); space(); name(n2);
  for (i = 0;i < 20;i += 4) {
    uint32_unpack_big(misc + i,&u);
    space(); number(u);
  }
  line();
}

void log_stats(uint64 *queries,uint64 *motion)
{
  string("stats ");
  number(*queries); space();
  number(*motion);
  line();
}
