#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "exit.h"
#include "cdb_make.h"
#include "open.h"
#include "stralloc.h"
#include "getln.h"
#include "strerr.h"
#include "byte.h"
#include "scan.h"
#include "fmt.h"
#include "ip4.h"

#define FATAL "rbldns-data: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}

int fd;
buffer b;
char bspace[1024];

int fdcdb;
struct cdb_make cdb;
static stralloc tmp;

static stralloc line;
int match = 1;
unsigned long linenum = 0;

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
  char ip[4];
  unsigned long u;
  unsigned int j;
  unsigned int k;
  char ch;

  umask(022);

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

    switch(line.s[0]) {
      default:
	syntaxerror(": unrecognized leading character");
      case '#':
	break;
      case ':':
	j = byte_chr(line.s + 1,line.len - 1,':');
	if (j >= line.len - 1) syntaxerror(": missing colon");
	if (ip4_scan(line.s + 1,ip) != j) syntaxerror(": malformed IP address");
	if (!stralloc_copyb(&tmp,ip,4)) nomem();
	if (!stralloc_catb(&tmp,line.s + j + 2,line.len - j - 2)) nomem();
        if (cdb_make_add(&cdb,"",0,tmp.s,tmp.len) == -1)
          die_datatmp();
        break;
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9':
	if (!stralloc_0(&line)) nomem();
	j = 0;
	if (!stralloc_copys(&tmp,"")) nomem();
	for (;;) {
	  k = scan_ulong(line.s + j,&u);
	  if (!k) break;
	  ch = u;
	  if (!stralloc_catb(&tmp,&ch,1)) nomem();
	  j += k;
	  if (line.s[j] != '.') break;
	  ++j;
	}
	if (!stralloc_catb(&tmp,"\0\0\0\0",4)) nomem();
	tmp.len = 4;
	if (line.s[j] == '/')
	  scan_ulong(line.s + j + 1,&u);
	else
	  u = 32;
	if (u > 32) u = 32;
	ch = u;
	if (!stralloc_catb(&tmp,&ch,1)) nomem();
        if (cdb_make_add(&cdb,tmp.s,tmp.len,"",0) == -1)
          die_datatmp();
	break;
    }
  }

  if (cdb_make_finish(&cdb) == -1) die_datatmp();
  if (fsync(fdcdb) == -1) die_datatmp();
  if (close(fdcdb) == -1) die_datatmp(); /* NFS stupidity */
  if (rename("data.tmp","data.cdb") == -1)
    strerr_die2sys(111,FATAL,"unable to move data.tmp to data.cdb: ");

  _exit(0);
}
