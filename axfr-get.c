#include <stdio.h>
#include <unistd.h>
#include "uint32.h"
#include "uint16.h"
#include "stralloc.h"
#include "error.h"
#include "strerr.h"
#include "getln.h"
#include "buffer.h"
#include "exit.h"
#include "open.h"
#include "scan.h"
#include "byte.h"
#include "str.h"
#include "ip4.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "dns.h"

#define FATAL "axfr-get: fatal: "

void die_usage(void)
{
  strerr_die1x(100,"axfr-get: usage: axfr-get zone fn fn.tmp");
}
void die_generate(void)
{
  strerr_die2sys(111,FATAL,"unable to generate AXFR query: ");
}
void die_parse(void)
{
  strerr_die2sys(111,FATAL,"unable to parse AXFR results: ");
}
unsigned int x_copy(char *buf,unsigned int len,unsigned int pos,char *out,unsigned int outlen)
{
  pos = dns_packet_copy(buf,len,pos,out,outlen);
  if (!pos) die_parse();
  return pos;
}
unsigned int x_getname(char *buf,unsigned int len,unsigned int pos,char **out)
{
  pos = dns_packet_getname(buf,len,pos,out);
  if (!pos) die_parse();
  return pos;
}
unsigned int x_skipname(char *buf,unsigned int len,unsigned int pos)
{
  pos = dns_packet_skipname(buf,len,pos);
  if (!pos) die_parse();
  return pos;
}

static char *zone;
unsigned int zonelen;
char *fn;
char *fntmp;

void die_netread(void)
{
  strerr_die2sys(111,FATAL,"unable to read from network: ");
}
void die_netwrite(void)
{
  strerr_die2sys(111,FATAL,"unable to write to network: ");
}
void die_read(void)
{
  strerr_die4sys(111,FATAL,"unable to read ",fn,": ");
}
void die_write(void)
{
  strerr_die4sys(111,FATAL,"unable to write ",fntmp,": ");
}

int saferead(int fd,char *buf,unsigned int len)
{
  int r;
  r = timeoutread(60,fd,buf,len);
  if (r == 0) { errno = error_proto; die_parse(); }
  if (r <= 0) die_netread();
  return r;
}
int safewrite(int fd,char *buf,unsigned int len)
{
  int r;
  r = timeoutwrite(60,fd,buf,len);
  if (r <= 0) die_netwrite();
  return r;
}
char netreadspace[1024];
buffer netread = BUFFER_INIT(saferead,6,netreadspace,sizeof netreadspace);
char netwritespace[1024];
buffer netwrite = BUFFER_INIT(safewrite,7,netwritespace,sizeof netwritespace);

void netget(char *buf,unsigned int len)
{
  int r;

  while (len > 0) {
    r = buffer_get(&netread,buf,len);
    buf += r; len -= r;
  }
}

int fd;
buffer b;
char bspace[1024];

void put(char *buf,unsigned int len)
{
  if (buffer_put(&b,buf,len) == -1) die_write();
}

int printable(char ch)
{
  if (ch == '.') return 1;
  if ((ch >= 'a') && (ch <= 'z')) return 1;
  if ((ch >= '0') && (ch <= '9')) return 1;
  if ((ch >= 'A') && (ch <= 'Z')) return 1;
  if (ch == '-') return 1;
  return 0;
}

static char *d1;
static char *d2;
static char *d3;

stralloc line;
int match;

int numsoa;

unsigned int doit(char *buf,unsigned int len,unsigned int pos)
{
  char data[20];
  uint32 ttl;
  uint16 dlen;
  uint16 typenum;
  uint32 u32;
  int i;

  pos = x_getname(buf,len,pos,&d1);
  pos = x_copy(buf,len,pos,data,10);
  uint16_unpack_big(data,&typenum);
  uint32_unpack_big(data + 4,&ttl);
  uint16_unpack_big(data + 8,&dlen);
  if (len - pos < dlen) { errno = error_proto; return 0; }
  len = pos + dlen;

  if (!dns_domain_suffix(d1,zone)) return len;
  if (byte_diff(data + 2,2,DNS_C_IN)) return len;

  if (byte_equal(data,2,DNS_T_SOA)) {
    if (++numsoa >= 2) return len;
    pos = x_getname(buf,len,pos,&d2);
    pos = x_getname(buf,len,pos,&d3);
    x_copy(buf,len,pos,data,20);
    uint32_unpack_big(data,&u32);
    if (!stralloc_copys(&line,"#")) return 0;
    if (!stralloc_catulong0(&line,u32,0)) return 0;
    if (!stralloc_cats(&line," auto axfr-get\n")) return 0;
    if (!stralloc_cats(&line,"Z")) return 0;
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,":")) return 0;
    if (!dns_domain_todot_cat(&line,d2)) return 0;
    if (!stralloc_cats(&line,".:")) return 0;
    if (!dns_domain_todot_cat(&line,d3)) return 0;
    if (!stralloc_cats(&line,".")) return 0;
    for (i = 0;i < 5;++i) {
      uint32_unpack_big(data + 4 * i,&u32);
      if (!stralloc_cats(&line,":")) return 0;
      if (!stralloc_catulong0(&line,u32,0)) return 0;
    }
  }
  else if (byte_equal(data,2,DNS_T_NS)) {
    if (!stralloc_copys(&line,"&")) return 0;
    if (byte_equal(d1,2,"\1*")) { errno = error_proto; return 0; }
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,"::")) return 0;
    x_getname(buf,len,pos,&d1);
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,".")) return 0;
  }
  else if (byte_equal(data,2,DNS_T_CNAME)) {
    if (!stralloc_copys(&line,"C")) return 0;
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,":")) return 0;
    x_getname(buf,len,pos,&d1);
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,".")) return 0;
  }
  else if (byte_equal(data,2,DNS_T_PTR)) {
    if (!stralloc_copys(&line,"^")) return 0;
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,":")) return 0;
    x_getname(buf,len,pos,&d1);
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,".")) return 0;
  }
  else if (byte_equal(data,2,DNS_T_MX)) {
    uint16 dist;
    if (!stralloc_copys(&line,"@")) return 0;
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,"::")) return 0;
    pos = x_copy(buf,len,pos,data,2);
    uint16_unpack_big(data,&dist);
    x_getname(buf,len,pos,&d1);
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,".:")) return 0;
    if (!stralloc_catulong0(&line,dist,0)) return 0;
  }
  else if (byte_equal(data,2,DNS_T_A) && (dlen == 4)) {
    char ipstr[IP4_FMT];
    if (!stralloc_copys(&line,"+")) return 0;
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,":")) return 0;
    x_copy(buf,len,pos,data,4);
    if (!stralloc_catb(&line,ipstr,ip4_fmt(ipstr,data))) return 0;
  }
  else {
    unsigned char ch;
    unsigned char ch2;
    if (!stralloc_copys(&line,":")) return 0;
    if (!dns_domain_todot_cat(&line,d1)) return 0;
    if (!stralloc_cats(&line,":")) return 0;
    if (!stralloc_catulong0(&line,typenum,0)) return 0;
    if (!stralloc_cats(&line,":")) return 0;
    for (i = 0;i < dlen;++i) {
      pos = x_copy(buf,len,pos,data,1);
      ch = data[0];
      if (printable(ch)) {
        if (!stralloc_catb(&line,&ch,1)) return 0;
      }
      else {
        if (!stralloc_cats(&line,"\\")) return 0;
        ch2 = '0' + ((ch >> 6) & 7);
        if (!stralloc_catb(&line,&ch2,1)) return 0;
        ch2 = '0' + ((ch >> 3) & 7);
        if (!stralloc_catb(&line,&ch2,1)) return 0;
        ch2 = '0' + (ch & 7);
        if (!stralloc_catb(&line,&ch2,1)) return 0;
      }
    }
  }
  if (!stralloc_cats(&line,":")) return 0;
  if (!stralloc_catulong0(&line,ttl,0)) return 0;
  if (!stralloc_cats(&line,"\n")) return 0;
  put(line.s,line.len);

  return len;
}

stralloc packet;

int main(int argc,char **argv)
{
  char out[20];
  unsigned long u;
  uint16 dlen;
  unsigned int pos;
  uint32 oldserial = 0;
  uint32 newserial = 0;
  uint16 numqueries;
  uint16 numanswers;

  if (!*argv) die_usage();

  if (!*++argv) die_usage();
  if (!dns_domain_fromdot(&zone,*argv,str_len(*argv))) die_generate();
  zonelen = dns_domain_length(zone);

  if (!*++argv) die_usage();
  fn = *argv;
  if (!*++argv) die_usage();
  fntmp = *argv;

  fd = open_read(fn);
  if (fd == -1) {
    if (errno != error_noent) die_read();
  }
  else {
    buffer_init(&b,buffer_unixread,fd,bspace,sizeof bspace);
    if (getln(&b,&line,&match,'\n') == -1) die_read();
    if (!stralloc_0(&line)) die_read();
    if (line.s[0] == '#') {
      scan_ulong(line.s + 1,&u);
      oldserial = u;
    }
    close(fd);
  }

  if (!stralloc_copyb(&packet,"\0\0\0\0\0\1\0\0\0\0\0\0",12)) die_generate();
  if (!stralloc_catb(&packet,zone,zonelen)) die_generate();
  if (!stralloc_catb(&packet,DNS_T_SOA DNS_C_IN,4)) die_generate();
  uint16_pack_big(out,packet.len);
  buffer_put(&netwrite,out,2);
  buffer_put(&netwrite,packet.s,packet.len);
  buffer_flush(&netwrite);

  netget(out,2);
  uint16_unpack_big(out,&dlen);
  if (!stralloc_ready(&packet,dlen)) die_parse();
  netget(packet.s,dlen);
  packet.len = dlen;

  pos = x_copy(packet.s,packet.len,0,out,12);
  uint16_unpack_big(out + 4,&numqueries);
  uint16_unpack_big(out + 6,&numanswers);

  while (numqueries) {
    --numqueries;
    pos = x_skipname(packet.s,packet.len,pos);
    pos += 4;
  }

  if (!numanswers) { errno = error_proto; die_parse(); }
  pos = x_getname(packet.s,packet.len,pos,&d1);
  if (!dns_domain_equal(zone,d1)) { errno = error_proto; die_parse(); }
  pos = x_copy(packet.s,packet.len,pos,out,10);
  if (byte_diff(out,4,DNS_T_SOA DNS_C_IN)) { errno = error_proto; die_parse(); }
  pos = x_skipname(packet.s,packet.len,pos);
  pos = x_skipname(packet.s,packet.len,pos);
  pos = x_copy(packet.s,packet.len,pos,out,4);

  uint32_unpack_big(out,&newserial);


  if (oldserial && newserial) /* allow 0 for very recently modified zones */
    if (oldserial == newserial) /* allow serial numbers to move backwards */
      _exit(0);


  fd = open_trunc(fntmp);
  if (fd == -1) die_write();
  buffer_init(&b,buffer_unixwrite,fd,bspace,sizeof bspace);

  if (!stralloc_copyb(&packet,"\0\0\0\0\0\1\0\0\0\0\0\0",12)) die_generate();
  if (!stralloc_catb(&packet,zone,zonelen)) die_generate();
  if (!stralloc_catb(&packet,DNS_T_AXFR DNS_C_IN,4)) die_generate();
  uint16_pack_big(out,packet.len);
  buffer_put(&netwrite,out,2);
  buffer_put(&netwrite,packet.s,packet.len);
  buffer_flush(&netwrite);

  numsoa = 0;
  while (numsoa < 2) {
    netget(out,2);
    uint16_unpack_big(out,&dlen);
    if (!stralloc_ready(&packet,dlen)) die_parse();
    netget(packet.s,dlen);
    packet.len = dlen;

    pos = x_copy(packet.s,packet.len,0,out,12);
    uint16_unpack_big(out + 4,&numqueries);

    while (numqueries) {
      --numqueries;
      pos = x_skipname(packet.s,packet.len,pos);
      pos += 4;
    }
    while (pos < packet.len) {
      pos = doit(packet.s,packet.len,pos);
      if (!pos) die_parse();
    }
  }

  if (buffer_flush(&b) == -1) die_write();
  if (fsync(fd) == -1) die_write();
  if (close(fd) == -1) die_write(); /* NFS dorks */
  if (rename(fntmp,fn) == -1)
    strerr_die6sys(111,FATAL,"unable to move ",fntmp," to ",fn,": ");
  _exit(0);
}
