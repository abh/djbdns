#include "env.h"
#include "exit.h"
#include "scan.h"
#include "strerr.h"
#include "error.h"
#include "ip4.h"
#include "uint16.h"
#include "socket.h"
#include "dns.h"
#include "byte.h"
#include "roots.h"
#include "fmt.h"
#include "iopause.h"
#include "query.h"
#include "alloc.h"
#include "response.h"
#include "cache.h"
#include "log.h"
#include "readwrite.h"
#include "okclient.h"
#include "droproot.h"

char myipoutgoing[4];
char myipincoming[4];

struct request {
  struct query q;
  struct taia timeout;
  iopause_fd *io;
  char ip[4]; /* send response to this address */
  uint16 port; /* send response to this port */
  char id[2];
  int tcp; /* TCP socket, or -1 for UDP */
  int tcpstate;
  char *tcpbuf; /* dynamically allocated */
  unsigned int tcplen;
  unsigned int tcppos;
} ;

#define MAXTCP 20
#define MAXREQ 200
static struct request req[MAXREQ];
char active[MAXREQ];
int numactive = 0;
int nextactive = MAXREQ - 1;
int numtcp = 0;

int udp53;
int tcp53;
char buf[1024];

static void request_free(struct request *x)
{
  if (active[x - req]) {
    active[x - req] = 0;
    --numactive;
  }
}

static void activate(struct request *x)
{
  if (!active[x - req]) {
    active[x - req] = 1;
    ++numactive;
  }
}

static int packetquery(char *buf,unsigned int len,char **q,char qtype[2],char id[2])
{
  unsigned int pos;
  char qclass[2];
  char header[12];

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) return 0;
  if (header[2] & 128) return 0; /* must not respond to responses */
  if (header[2] & 120) return 0;
  if (header[2] & 2) return 0;
  if (byte_diff(header + 4,2,"\0\1")) return 0;

  pos = dns_packet_getname(buf,len,pos,q); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) return 0;
  if (byte_diff(qclass,2,DNS_C_IN) && byte_diff(qclass,2,DNS_C_ANY)) return 0;

  byte_copy(id,2,header);
  return 1;
}

static void udpdrop(struct request *x)
{
  log_querydrop(x - req);
  request_free(x);
}

static void udprespond(struct request *x)
{
  response_id(x->id);
  if (response_len > 512)
    response_tc();
  socket_send4(udp53,response,response_len,x->ip,x->port);
  log_querydone(x - req,response_len);
  request_free(x);
}

static void tcpdrop(struct request *x)
{
  log_conndrop(x - req);
  close(x->tcp);
  --numtcp;
  request_free(x);
}

static void handle(struct request *x,struct taia *stamp)
{
  static char *q = 0;
  char qtype[2];
  char ch;
  int r;

  errno = error_io;

  if (!active[x - req]) return;

  if (x->tcp == -1) {
    r = query_get(&x->q,x->io,stamp);
    if (r == -1) udpdrop(x);
    if (r == 1) udprespond(x);
    return;
  }

  if (x->io->revents) {
    struct taia now;
    taia_now(&now);
    taia_uint(&x->timeout,10);
    taia_add(&x->timeout,&x->timeout,&now);
  }
  else
    if (x->tcpstate)
      if (taia_less(stamp,&x->timeout))
	return;

  switch(x->tcpstate) {
    case 1:
/*
normal state at beginning of TCP connection
*/
      r = read(x->tcp,&ch,1);
      if (r <= 0) { tcpdrop(x); return; }
      x->tcplen = (unsigned char) ch;
      x->tcplen <<= 8;
      x->tcpstate = 2;
      return;

    case 2:
/*
have received one byte of TCP query packet length into x->tcplen
*/
      r = read(x->tcp,&ch,1);
      if (r <= 0) { tcpdrop(x); return; }
      x->tcplen += (unsigned char) ch;
      x->tcpbuf = alloc(x->tcplen);
      if (!x->tcpbuf) { tcpdrop(x); return; }
      x->tcppos = 0;
      x->tcpstate = 3;
      return;

    case 3:
/*
have received TCP query packet length into x->tcplen
x->tcpbuf is dynamically allocated of length x->tcplen
have received x->tcppos bytes of query packet
*/
      r = read(x->tcp,x->tcpbuf + x->tcppos,x->tcplen - x->tcppos);
      if (r <= 0) { alloc_free(x->tcpbuf); tcpdrop(x); return; }
      x->tcppos += r;
      if (x->tcppos == x->tcplen) {
        if (!packetquery(x->tcpbuf,x->tcplen,&q,qtype,x->id)) {
	  alloc_free(x->tcpbuf); tcpdrop(x); return;
	}

        log_query(x - req,x->ip,x->port,x->id,q,qtype);

        switch(query_start(&x->q,q,qtype,myipoutgoing)) {
          case -1:
	    alloc_free(x->tcpbuf);
	    tcpdrop(x);
	    return;
          case 1:
	    alloc_free(x->tcpbuf);
	    goto HAVERESPONSE;
	  default:
	    alloc_free(x->tcpbuf);
	    x->tcpstate = 0;
	    return;
        }
      }
      return;

    case 0:
/*
handling query
*/
      switch(query_get(&x->q,x->io,stamp)) {
        case -1:
	  tcpdrop(x);
	  return;
        case 1:
	  HAVERESPONSE:
	  response_id(x->id);
	  x->tcplen = response_len + 2;
	  x->tcpbuf = alloc(response_len + 2);
	  if (!x->tcpbuf) { tcpdrop(x); return; }
	  uint16_pack_big(x->tcpbuf,response_len);
	  byte_copy(x->tcpbuf + 2,response_len,response);
	  x->tcppos = 0;
	  x->tcpstate = -1;
	  return;
      }
      return;

    case -1:
/*
x->tcpbuf is dynamically allocated of length x->tcplen
have written x->tcppos bytes of buf
*/
      r = write(x->tcp,x->tcpbuf + x->tcppos,x->tcplen - x->tcppos);
      if (r <= 0) { alloc_free(x->tcpbuf); tcpdrop(x); return; }
      x->tcppos += r;
      if (x->tcppos == x->tcplen) {
        log_querydone(x - req,x->tcplen);
	alloc_free(x->tcpbuf);
	x->tcpstate = 1; /* XXX: drop connection immediately? */
      }
      return;
  }
}

static void prep(struct request *x,struct taia *deadline,struct taia *stamp)
{
  if ((x->tcp == -1) || (x->tcpstate == 0)) {
    query_io(&x->q,x->io,deadline);
    return;
  }

  if (taia_less(&x->timeout,deadline)) *deadline = x->timeout;

  x->io->fd = x->tcp;
  x->io->events = (x->tcpstate > 0) ? IOPAUSE_READ : IOPAUSE_WRITE;
}

static void udpquery(void)
{
  struct request *x;
  int len;
  static char *q = 0;
  char qtype[2];

  if (numactive >= MAXREQ) return;
  do
    if (++nextactive >= MAXREQ)
      nextactive = 0;
  while (active[nextactive]);
  x = req + nextactive;

  len = socket_recv4(udp53,buf,sizeof buf,x->ip,&x->port);
  if (len == -1) return;
  if (len >= sizeof buf) return;
  if (x->port < 1024) if (x->port != 53) return;
  if (!okclient(x->ip)) return;
  x->tcp = -1;

  if (!packetquery(buf,len,&q,qtype,x->id)) return;

  activate(x);
  log_query(x - req,x->ip,x->port,x->id,q,qtype);
  switch(query_start(&x->q,q,qtype,myipoutgoing)) {
    case -1:
      udpdrop(x);
      return;
    case 1:
      udprespond(x);
  }
}

static void tcpconnection(void)
{
  struct request *x;
  struct taia now;

  if (numtcp >= MAXTCP) return;
  if (numactive >= MAXREQ) return;
  do
    if (++nextactive >= MAXREQ)
      nextactive = 0;
  while (active[nextactive]);
  x = req + nextactive;

  x->tcp = socket_accept4(tcp53,x->ip,&x->port);
  if (x->tcp == -1) return;
  if (x->port < 1024) if (x->port != 53) { close(x->tcp); return; }
  if (!okclient(x->ip)) { close(x->tcp); return; }

  ++numtcp;
  x->tcpstate = 1;
  activate(x);

  taia_now(&now);
  taia_uint(&x->timeout,10);
  taia_add(&x->timeout,&x->timeout,&now);

  log_conn(x - req,x->ip,x->port);
}

iopause_fd io[3 + MAXREQ];
iopause_fd *udp53io;
iopause_fd *tcp53io;

static void doit(void)
{
  int j;
  struct taia deadline;
  struct taia stamp;
  int iolen;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);

    iolen = 0;

    udp53io = 0;
    tcp53io = 0;
    if (numactive < MAXREQ) {
      udp53io = io + iolen++;
      udp53io->fd = udp53;
      udp53io->events = IOPAUSE_READ;
    }
    if ((numactive < MAXREQ) && (numtcp < MAXTCP)) {
      tcp53io = io + iolen++;
      tcp53io->fd = tcp53;
      tcp53io->events = IOPAUSE_READ;
    }

    for (j = 0;j < MAXREQ;++j)
      if (active[j]) {
	req[j].io = io + iolen++;
	prep(req + j,&deadline,&stamp);
      }

    iopause(io,iolen,&deadline,&stamp);

    for (j = 0;j < MAXREQ;++j)
      if (active[j])
	handle(&req[j],&stamp);

    if (udp53io)
      if (udp53io->revents)
	udpquery();

    if (tcp53io)
      if (tcp53io->revents)
	tcpconnection();
  }
}

#define FATAL "dnscache: fatal: "

char seed[128];

main()
{
  char *x;
  unsigned long cachesize;

  x = env_get("IP");
  if (!x)
    strerr_die2x(111,FATAL,"$IP not set");
  if (!ip4_scan(x,myipincoming))
    strerr_die3x(111,FATAL,"unable to parse IP address ",x);

  udp53 = socket_udp();
  if (udp53 == -1)
    strerr_die2sys(111,FATAL,"unable to create UDP socket: ");
  if (socket_bind4_reuse(udp53,myipincoming,53) == -1)
    strerr_die2sys(111,FATAL,"unable to bind UDP socket: ");

  tcp53 = socket_tcp();
  if (tcp53 == -1)
    strerr_die2sys(111,FATAL,"unable to create TCP socket: ");
  if (socket_bind4_reuse(tcp53,myipincoming,53) == -1)
    strerr_die2sys(111,FATAL,"unable to bind TCP socket: ");

  droproot(FATAL);

  socket_tryreservein(udp53,131072);

  byte_zero(seed,sizeof seed);
  read(0,seed,sizeof seed);
  dns_random_init(seed);
  close(0);

  x = env_get("IPSEND");
  if (!x)
    strerr_die2x(111,FATAL,"$IPSEND not set");
  if (!ip4_scan(x,myipoutgoing))
    strerr_die3x(111,FATAL,"unable to parse IP address ",x);

  x = env_get("CACHESIZE");
  if (!x)
    strerr_die2x(111,FATAL,"$CACHESIZE not set");
  scan_ulong(x,&cachesize);
  if (!cache_init(cachesize))
    strerr_die3x(111,FATAL,"not enough memory for cache of size ",x);

  if (!roots_init())
    strerr_die2sys(111,FATAL,"unable to read servers: ");

  if (socket_listen(tcp53,20) == -1)
    strerr_die2sys(111,FATAL,"unable to listen on TCP socket: ");

  log_startup();
  doit();
}
