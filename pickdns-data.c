#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "exit.h"
#include "cdb_make.h"
#include "open.h"
#include "alloc.h"
#include "gen_allocdefs.h"
#include "stralloc.h"
#include "getln.h"
#include "case.h"
#include "strerr.h"
#include "str.h"
#include "byte.h"
#include "scan.h"
#include "fmt.h"
#include "ip4.h"
#include "dns.h"

#define FATAL "pickdns-data: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
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

struct address {
  char *name;
  unsigned int namelen;
  char ip[4];
  char location[2];
} ;

int address_diff(struct address *p,struct address *q)
{
  int r;

  r = byte_diff(p->location,2,q->location);
  if (r < 0) return -1;
  if (r > 0) return 1;
  if (p->namelen < q->namelen) return -1;
  if (p->namelen > q->namelen) return 1;
  return case_diffb(p->name,p->namelen,q->name);
}

void address_sort(struct address *z,unsigned int n)
{
  unsigned int i;
  unsigned int j;
  unsigned int p;
  unsigned int q;
  struct address t;

  i = j = n;
  --z;

  while (j > 1) {
    if (i > 1) { --i; t = z[i]; }
    else { t = z[j]; z[j] = z[i]; --j; }
    q = i;
    while ((p = q * 2) < j) {
      if (address_diff(&z[p + 1],&z[p]) >= 0) ++p;
      z[q] = z[p]; q = p;
    }
    if (p == j) {
      z[q] = z[p]; q = p;
    }
    while ((q > i) && (address_diff(&t,&z[p = q/2]) > 0)) {
      z[q] = z[p]; q = p;
    }
    z[q] = t;
  }
}

GEN_ALLOC_typedef(address_alloc,struct address,s,len,a)
GEN_ALLOC_readyplus(address_alloc,struct address,s,len,a,i,n,x,30,address_alloc_readyplus)
GEN_ALLOC_append(address_alloc,struct address,s,len,a,i,n,x,30,address_alloc_readyplus,address_alloc_append)

static address_alloc x;

int fd;
buffer b;
char bspace[1024];

int fdcdb;
struct cdb_make cdb;
static stralloc key;
static stralloc result;

static stralloc line;
int match = 1;
unsigned long linenum = 0;

#define NUMFIELDS 3
static stralloc f[NUMFIELDS];

char strnum[FMT_ULONG];

void syntaxerror(const char *why)
{
  strnum[fmt_ulong(strnum,linenum)] = 0;
  strerr_die4x(111,FATAL,"unable to parse data line ",strnum,why);
}
void die_datatmp(void)
{
  strerr_die2sys(111,FATAL,"unable to create data.tmp: ");
}

int main()
{
  struct address t;
  int i;
  int j;
  int k;
  char ch;

  umask(022);

  if (!address_alloc_readyplus(&x,0)) nomem();

  fd = open_read("data");
  if (fd == -1) strerr_die2sys(111,FATAL,"unable to open data: ");
  buffer_init(&b,buffer_unixread,fd,bspace,sizeof bspace);

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
      default:
	syntaxerror(": unrecognized leading character");
      case '#':
	break;
      case '-':
        break;
      case '+':
	byte_zero(&t,sizeof t);
	if (!dns_domain_fromdot(&t.name,f[0].s,f[0].len)) nomem();
	t.namelen = dns_domain_length(t.name);
	case_lowerb(t.name,t.namelen);
	if (!stralloc_0(&f[1])) nomem();
	if (!ip4_scan(f[1].s,t.ip)) syntaxerror(": malformed IP address");
	if (!stralloc_0(&f[2])) nomem();
	if (!stralloc_0(&f[2])) nomem();
	byte_copy(t.location,2,f[2].s);
	if (!address_alloc_append(&x,&t)) nomem();
	break;
      case '%':
	if (!stralloc_0(&f[0])) nomem();
	if (!stralloc_0(&f[0])) nomem();
	if (!stralloc_copyb(&result,f[0].s,2)) nomem();
	if (!stralloc_0(&f[1])) nomem();
	if (!stralloc_copys(&key,"%")) nomem();
	ipprefix_cat(&key,f[1].s);
        if (cdb_make_add(&cdb,key.s,key.len,result.s,result.len) == -1)
          die_datatmp();
	break;
    }
  }

  close(fd);
  address_sort(x.s,x.len);

  i = 0;
  while (i < x.len) {
    for (j = i + 1;j < x.len;++j)
      if (address_diff(x.s + i,x.s + j))
	break;
    if (!stralloc_copys(&key,"+")) nomem();
    if (!stralloc_catb(&key,x.s[i].location,2)) nomem();
    if (!stralloc_catb(&key,x.s[i].name,x.s[i].namelen)) nomem();
    if (!stralloc_copys(&result,"")) nomem();
    while (i < j)
      if (!stralloc_catb(&result,x.s[i++].ip,4)) nomem();
    if (cdb_make_add(&cdb,key.s,key.len,result.s,result.len) == -1)
      die_datatmp();
  }

  if (cdb_make_finish(&cdb) == -1) die_datatmp();
  if (fsync(fdcdb) == -1) die_datatmp();
  if (close(fdcdb) == -1) die_datatmp(); /* NFS stupidity */
  if (rename("data.tmp","data.cdb") == -1)
    strerr_die2sys(111,FATAL,"unable to move data.tmp to data.cdb: ");

  _exit(0);
}
