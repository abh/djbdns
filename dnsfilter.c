#include <unistd.h>
#include "strerr.h"
#include "buffer.h"
#include "stralloc.h"
#include "alloc.h"
#include "dns.h"
#include "ip4.h"
#include "byte.h"
#include "scan.h"
#include "taia.h"
#include "sgetopt.h"
#include "iopause.h"
#include "error.h"
#include "exit.h"

#define FATAL "dnsfilter: fatal: "

void nomem(void)
{
  strerr_die2x(111,FATAL,"out of memory");
}

struct line {
  stralloc left;
  stralloc middle;
  stralloc right;
  struct dns_transmit dt;
  int flagactive;
  iopause_fd *io;
} *x;
struct line tmp;
unsigned int xmax = 1000;
unsigned int xnum = 0;
unsigned int numactive = 0;
unsigned int maxactive = 10;

static stralloc partial;

char inbuf[1024];
int inbuflen = 0;
iopause_fd *inio;
int flag0 = 1;

iopause_fd *io;
int iolen;

char servers[64];
char ip[4];
char name[DNS_NAME4_DOMAIN];

void errout(int i)
{
  int j;

  if (!stralloc_copys(&x[i].middle,":")) nomem();
  if (!stralloc_cats(&x[i].middle,error_str(errno))) nomem();
  for (j = 0;j < x[i].middle.len;++j)
    if (x[i].middle.s[j] == ' ')
      x[i].middle.s[j] = '-';
}

int main(int argc,char **argv)
{
  struct taia stamp;
  struct taia deadline;
  int opt;
  unsigned long u;
  int i;
  int j;
  int r;

  while ((opt = getopt(argc,argv,"c:l:")) != opteof)
    switch(opt) {
      case 'c':
	scan_ulong(optarg,&u);
	if (u < 1) u = 1;
	if (u > 1000) u = 1000;
	maxactive = u;
	break;
      case 'l':
	scan_ulong(optarg,&u);
	if (u < 1) u = 1;
	if (u > 1000000) u = 1000000;
	xmax = u;
	break;
      default:
	strerr_die1x(111,"dnsfilter: usage: dnsfilter [ -c concurrency ] [ -l lines ]");
    }

  x = (struct line *) alloc(xmax * sizeof(struct line));
  if (!x) nomem();
  byte_zero(x,xmax * sizeof(struct line));

  io = (iopause_fd *) alloc((xmax + 1) * sizeof(iopause_fd)); 
  if (!io) nomem();

  if (!stralloc_copys(&partial,"")) nomem();


  while (flag0 || inbuflen || partial.len || xnum) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);

    iolen = 0;

    if (flag0)
      if (inbuflen < sizeof inbuf) {
        inio = io + iolen++;
        inio->fd = 0;
        inio->events = IOPAUSE_READ;
      }

    for (i = 0;i < xnum;++i)
      if (x[i].flagactive) {
	x[i].io = io + iolen++;
	dns_transmit_io(&x[i].dt,x[i].io,&deadline);
      }

    iopause(io,iolen,&deadline,&stamp);

    if (flag0)
      if (inbuflen < sizeof inbuf)
        if (inio->revents) {
	  r = read(0,inbuf + inbuflen,(sizeof inbuf) - inbuflen);
	  if (r <= 0)
	    flag0 = 0;
	  else
	    inbuflen += r;
        }
    
    for (i = 0;i < xnum;++i)
      if (x[i].flagactive) {
	r = dns_transmit_get(&x[i].dt,x[i].io,&stamp);
	if (r == -1) {
	  errout(i);
	  x[i].flagactive = 0;
	  --numactive;
	}
	else if (r == 1) {
	  if (dns_name_packet(&x[i].middle,x[i].dt.packet,x[i].dt.packetlen) == -1)
	    errout(i);
	  if (x[i].middle.len)
	    if (!stralloc_cats(&x[i].left,"=")) nomem();
	  x[i].flagactive = 0;
	  --numactive;
	}
      }

    for (;;) {

      if (xnum && !x[0].flagactive) {
        buffer_put(buffer_1,x[0].left.s,x[0].left.len);
        buffer_put(buffer_1,x[0].middle.s,x[0].middle.len);
        buffer_put(buffer_1,x[0].right.s,x[0].right.len);
        buffer_flush(buffer_1);
        --xnum;
        tmp = x[0];
        for (i = 0;i < xnum;++i) x[i] = x[i + 1];
        x[xnum] = tmp;
	continue;
      }

      if ((xnum < xmax) && (numactive < maxactive)) {
        i = byte_chr(inbuf,inbuflen,'\n');
        if (inbuflen && (i == inbuflen)) {
	  if (!stralloc_catb(&partial,inbuf,inbuflen)) nomem();
	  inbuflen = 0;
	  continue;
        }

	if ((i < inbuflen) || (!flag0 && partial.len)) {
	  if (i < inbuflen) ++i;
	  if (!stralloc_catb(&partial,inbuf,i)) nomem();
	  inbuflen -= i;
	  for (j = 0;j < inbuflen;++j) inbuf[j] = inbuf[j + i];
  
	  if (partial.len) {
	    i = byte_chr(partial.s,partial.len,'\n');
	    i = byte_chr(partial.s,i,'\t');
	    i = byte_chr(partial.s,i,' ');
    
	    if (!stralloc_copyb(&x[xnum].left,partial.s,i)) nomem();
	    if (!stralloc_copys(&x[xnum].middle,"")) nomem();
	    if (!stralloc_copyb(&x[xnum].right,partial.s + i,partial.len - i)) nomem();
	    x[xnum].flagactive = 0;
  
	    partial.len = i;
	    if (!stralloc_0(&partial)) nomem();
	    if (ip4_scan(partial.s,ip)) {
	      dns_name4_domain(name,ip);
	      if (dns_resolvconfip(servers) == -1)
	        strerr_die2sys(111,FATAL,"unable to read /etc/resolv.conf: ");
	      if (dns_transmit_start(&x[xnum].dt,servers,1,name,DNS_T_PTR,"\0\0\0\0") == -1)
	        errout(xnum);
	      else {
	        x[xnum].flagactive = 1;
	        ++numactive;
	      }
	    }
	    ++xnum;
	  }
  
	  partial.len = 0;
	  continue;
	}
      }

      break;
    }
  }

  _exit(0);
}
