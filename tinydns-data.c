#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "uint16.h"
#include "uint32.h"
#include "str.h"
#include "byte.h"
#include "fmt.h"
#include "ip4.h"
#include "exit.h"
#include "case.h"
#include "scan.h"
#include "buffer.h"
#include "strerr.h"
#include "getln.h"
#include "cdb_make.h"
#include "stralloc.h"
#include "open.h"
#include "dns.h"

#define TTL_NS 259200
#define TTL_POSITIVE 86400
#define TTL_NEGATIVE 2560

#define FATAL "tinydns-data: fatal: "

void die_datatmp(void)
{
  strerr_die2sys(111,FATAL,"unable to create data.tmp: ");
}
void nomem(void)
{
  strerr_die1sys(111,FATAL);
}

void ttdparse(stralloc *sa,char ttd[8])
{
  unsigned int i;
  char ch;

  byte_zero(ttd,8);
  for (i = 0;(i < 16) && (i < sa->len);++i) {
    ch = sa->s[i];
    if ((ch >= '0') && (ch <= '9'))
      ch -= '0';
    else if ((ch >= 'a') && (ch <= 'f'))
      ch -= 'a' - 10;
    else
      ch = 0;
    if (!(i & 1)) ch <<= 4;
    ttd[i >> 1] |= ch;
  }
}

void locparse(stralloc *sa,char loc[2])
{
  loc[0] = (sa->len > 0) ? sa->s[0] : 0;
  loc[1] = (sa->len > 1) ? sa->s[1] : 0;
}

void ipprefix_cat(stralloc *out,char *s)
{
  unsigned long u;
  char ch;
  unsigned int j;

  for (;;)
    if (*s == '.')
      ++s;
    else {
      j = scan_ulong(s,&u);
      if (!j) return;
      s += j;
      ch = u;
      if (!stralloc_catb(out,&ch,1)) nomem();
    }
}

void txtparse(stralloc *sa)
{
  char ch;
  unsigned int i;
  unsigned int j;

  j = 0;
  i = 0;
  while (i < sa->len) {
    ch = sa->s[i++];
    if (ch == '\\') {
      if (i >= sa->len) break;
      ch = sa->s[i++];
      if ((ch >= '0') && (ch <= '7')) {
        ch -= '0';
        if ((i < sa->len) && (sa->s[i] >= '0') && (sa->s[i] <= '7')) {
	  ch <<= 3;
	  ch += sa->s[i++] - '0';
          if ((i < sa->len) && (sa->s[i] >= '0') && (sa->s[i] <= '7')) {
	    ch <<= 3;
	    ch += sa->s[i++] - '0';
          }
        }
      }
    }
    sa->s[j++] = ch;
  }
  sa->len = j;
}

char defaultsoa[20];

void defaultsoa_init(int fd)
{
  struct stat st;
  if (fstat(fd,&st) == -1)
    strerr_die2sys(111,FATAL,"unable to stat data: ");
  uint32_pack_big(defaultsoa,st.st_mtime);
  if (byte_equal(defaultsoa,4,"\0\0\0\0"))
    defaultsoa[3] = 1;
  byte_copy(defaultsoa + 4,16,"\0\0\100\000\0\0\010\000\0\020\000\000\0\0\012\000");
}

int fdcdb;
struct cdb_make cdb;
static stralloc key;
static stralloc result;

void rr_add(const char *buf,unsigned int len)
{
  if (!stralloc_catb(&result,buf,len)) nomem();
}
void rr_addname(const char *d)
{
  rr_add(d,dns_domain_length(d));
}
void rr_start(const char type[2],unsigned long ttl,const char ttd[8],const char loc[2])
{
  char buf[4];
  if (!stralloc_copyb(&result,type,2)) nomem();
  if (byte_equal(loc,2,"\0\0"))
    rr_add("=",1);
  else {
    rr_add(">",1);
    rr_add(loc,2);
  }
  uint32_pack_big(buf,ttl);
  rr_add(buf,4);
  rr_add(ttd,8);
}
void rr_finish(const char *owner)
{
  if (byte_equal(owner,2,"\1*")) {
    owner += 2;
    result.s[2] -= 19;
  }
  if (!stralloc_copyb(&key,owner,dns_domain_length(owner))) nomem();
  case_lowerb(key.s,key.len);
  if (cdb_make_add(&cdb,key.s,key.len,result.s,result.len) == -1)
    die_datatmp();
}

buffer b;
char bspace[1024];

static stralloc line;
int match = 1;
unsigned long linenum = 0;

#define NUMFIELDS 15
static stralloc f[NUMFIELDS];

static char *d1;
static char *d2;
char dptr[DNS_NAME4_DOMAIN];

char strnum[FMT_ULONG];

void syntaxerror(const char *why)
{
  strnum[fmt_ulong(strnum,linenum)] = 0;
  strerr_die4x(111,FATAL,"unable to parse data line ",strnum,why);
}

int main()
{
  int fddata;
  int i;
  int j;
  int k;
  char ch;
  unsigned long ttl;
  char ttd[8];
  char loc[2];
  unsigned long u;
  char ip[4];
  char type[2];
  char soa[20];
  char buf[4];

  umask(022);

  fddata = open_read("data");
  if (fddata == -1)
    strerr_die2sys(111,FATAL,"unable to open data: ");
  defaultsoa_init(fddata);

  buffer_init(&b,buffer_unixread,fddata,bspace,sizeof bspace);

  fdcdb = open_trunc("data.tmp");
  if (fdcdb == -1) die_datatmp();
  if (cdb_make_start(&cdb,fdcdb) == -1) die_datatmp();

  while (match) {
    ++linenum;
    if (getln(&b,&line,&match,'\n') == -1)
      strerr_die2sys(111,FATAL,"unable to read line: ");

    while (line.len) {
      ch = line.s[line.len - 1];
      if ((ch != ' ') && (ch != '\t') && (ch != '\n')) break;
      --line.len;
    }
    if (!line.len) continue;
    if (line.s[0] == '#') continue;
    if (line.s[0] == '-') continue;

    j = 1;
    for (i = 0;i < NUMFIELDS;++i) {
      if (j >= line.len) {
	if (!stralloc_copys(&f[i],"")) nomem();
      }
      else {
        k = byte_chr(line.s + j,line.len - j,':');
	if (!stralloc_copyb(&f[i],line.s + j,k)) nomem();
	j += k + 1;
      }
    }

    switch(line.s[0]) {

      case '%':
	locparse(&f[0],loc);
	if (!stralloc_copyb(&key,"\0%",2)) nomem();
	if (!stralloc_0(&f[1])) nomem();
	ipprefix_cat(&key,f[1].s);
        if (cdb_make_add(&cdb,key.s,key.len,loc,2) == -1)
          die_datatmp();
	break;

      case 'Z':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();

	if (!stralloc_0(&f[3])) nomem();
	if (!scan_ulong(f[3].s,&u)) uint32_unpack_big(defaultsoa,&u);
	uint32_pack_big(soa,u);
	if (!stralloc_0(&f[4])) nomem();
	if (!scan_ulong(f[4].s,&u)) uint32_unpack_big(defaultsoa + 4,&u);
	uint32_pack_big(soa + 4,u);
	if (!stralloc_0(&f[5])) nomem();
	if (!scan_ulong(f[5].s,&u)) uint32_unpack_big(defaultsoa + 8,&u);
	uint32_pack_big(soa + 8,u);
	if (!stralloc_0(&f[6])) nomem();
	if (!scan_ulong(f[6].s,&u)) uint32_unpack_big(defaultsoa + 12,&u);
	uint32_pack_big(soa + 12,u);
	if (!stralloc_0(&f[7])) nomem();
	if (!scan_ulong(f[7].s,&u)) uint32_unpack_big(defaultsoa + 16,&u);
	uint32_pack_big(soa + 16,u);

	if (!stralloc_0(&f[8])) nomem();
	if (!scan_ulong(f[8].s,&ttl)) ttl = TTL_NEGATIVE;
	ttdparse(&f[9],ttd);
	locparse(&f[10],loc);

	rr_start(DNS_T_SOA,ttl,ttd,loc);
	if (!dns_domain_fromdot(&d2,f[1].s,f[1].len)) nomem();
	rr_addname(d2);
	if (!dns_domain_fromdot(&d2,f[2].s,f[2].len)) nomem();
	rr_addname(d2);
	rr_add(soa,20);
	rr_finish(d1);
	break;

      case '.': case '&':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();
	if (!stralloc_0(&f[3])) nomem();
	if (!scan_ulong(f[3].s,&ttl)) ttl = TTL_NS;
	ttdparse(&f[4],ttd);
	locparse(&f[5],loc);

	if (!stralloc_0(&f[1])) nomem();

	if (byte_chr(f[2].s,f[2].len,'.') >= f[2].len) {
	  if (!stralloc_cats(&f[2],".ns.")) nomem();
	  if (!stralloc_catb(&f[2],f[0].s,f[0].len)) nomem();
	}
	if (!dns_domain_fromdot(&d2,f[2].s,f[2].len)) nomem();

	if (line.s[0] == '.') {
	  rr_start(DNS_T_SOA,ttl ? TTL_NEGATIVE : 0,ttd,loc);
	  rr_addname(d2);
	  rr_add("\12hostmaster",11);
	  rr_addname(d1);
	  rr_add(defaultsoa,20);
	  rr_finish(d1);
	}

	rr_start(DNS_T_NS,ttl,ttd,loc);
	rr_addname(d2);
	rr_finish(d1);

	if (ip4_scan(f[1].s,ip)) {
	  rr_start(DNS_T_A,ttl,ttd,loc);
	  rr_add(ip,4);
	  rr_finish(d2);
	}

	break;

      case '+': case '=':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();
	if (!stralloc_0(&f[2])) nomem();
	if (!scan_ulong(f[2].s,&ttl)) ttl = TTL_POSITIVE;
	ttdparse(&f[3],ttd);
	locparse(&f[4],loc);

	if (!stralloc_0(&f[1])) nomem();

	if (ip4_scan(f[1].s,ip)) {
	  rr_start(DNS_T_A,ttl,ttd,loc);
	  rr_add(ip,4);
	  rr_finish(d1);

	  if (line.s[0] == '=') {
	    dns_name4_domain(dptr,ip);
	    rr_start(DNS_T_PTR,ttl,ttd,loc);
	    rr_addname(d1);
	    rr_finish(dptr);
	  }
	}
	break;

      case '@':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();
	if (!stralloc_0(&f[4])) nomem();
	if (!scan_ulong(f[4].s,&ttl)) ttl = TTL_POSITIVE;
	ttdparse(&f[5],ttd);
	locparse(&f[6],loc);

	if (!stralloc_0(&f[1])) nomem();

	if (byte_chr(f[2].s,f[2].len,'.') >= f[2].len) {
	  if (!stralloc_cats(&f[2],".mx.")) nomem();
	  if (!stralloc_catb(&f[2],f[0].s,f[0].len)) nomem();
	}
	if (!dns_domain_fromdot(&d2,f[2].s,f[2].len)) nomem();

	if (!stralloc_0(&f[3])) nomem();
	if (!scan_ulong(f[3].s,&u)) u = 0;

	rr_start(DNS_T_MX,ttl,ttd,loc);
	uint16_pack_big(buf,u);
	rr_add(buf,2);
	rr_addname(d2);
	rr_finish(d1);

	if (ip4_scan(f[1].s,ip)) {
	  rr_start(DNS_T_A,ttl,ttd,loc);
	  rr_add(ip,4);
	  rr_finish(d2);
	}
	break;

      case '^': case 'C':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();
	if (!dns_domain_fromdot(&d2,f[1].s,f[1].len)) nomem();
	if (!stralloc_0(&f[2])) nomem();
	if (!scan_ulong(f[2].s,&ttl)) ttl = TTL_POSITIVE;
	ttdparse(&f[3],ttd);
	locparse(&f[4],loc);

	if (line.s[0] == 'C')
	  rr_start(DNS_T_CNAME,ttl,ttd,loc);
	else
	  rr_start(DNS_T_PTR,ttl,ttd,loc);
	rr_addname(d2);
	rr_finish(d1);
	break;

      case '\'':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();
	if (!stralloc_0(&f[2])) nomem();
	if (!scan_ulong(f[2].s,&ttl)) ttl = TTL_POSITIVE;
	ttdparse(&f[3],ttd);
	locparse(&f[4],loc);

	rr_start(DNS_T_TXT,ttl,ttd,loc);

	txtparse(&f[1]);
	i = 0;
	while (i < f[1].len) {
	  k = f[1].len - i;
	  if (k > 127) k = 127;
	  ch = k;
	  rr_add(&ch,1);
	  rr_add(f[1].s + i,k);
	  i += k;
	}

	rr_finish(d1);
	break;

      case ':':
	if (!dns_domain_fromdot(&d1,f[0].s,f[0].len)) nomem();
	if (!stralloc_0(&f[3])) nomem();
	if (!scan_ulong(f[3].s,&ttl)) ttl = TTL_POSITIVE;
	ttdparse(&f[4],ttd);
	locparse(&f[5],loc);

	if (!stralloc_0(&f[1])) nomem();
	scan_ulong(f[1].s,&u);
	uint16_pack_big(type,u);
	if (byte_equal(type,2,DNS_T_AXFR))
	  syntaxerror(": type AXFR prohibited");
	if (byte_equal(type,2,"\0\0"))
	  syntaxerror(": type 0 prohibited");
	if (byte_equal(type,2,DNS_T_SOA))
	  syntaxerror(": type SOA prohibited");
	if (byte_equal(type,2,DNS_T_NS))
	  syntaxerror(": type NS prohibited");
	if (byte_equal(type,2,DNS_T_CNAME))
	  syntaxerror(": type CNAME prohibited");
	if (byte_equal(type,2,DNS_T_PTR))
	  syntaxerror(": type PTR prohibited");
	if (byte_equal(type,2,DNS_T_MX))
	  syntaxerror(": type MX prohibited");

	txtparse(&f[2]);

	rr_start(type,ttl,ttd,loc);
	rr_add(f[2].s,f[2].len);
	rr_finish(d1);
	break;

      default:
        syntaxerror(": unrecognized leading character");
    }
  }

  if (cdb_make_finish(&cdb) == -1) die_datatmp();
  if (fsync(fdcdb) == -1) die_datatmp();
  if (close(fdcdb) == -1) die_datatmp(); /* NFS stupidity */
  if (rename("data.tmp","data.cdb") == -1)
    strerr_die2sys(111,FATAL,"unable to move data.tmp to data.cdb: ");

  _exit(0);
}
