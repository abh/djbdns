#ifndef QUERY_H
#define QUERY_H

#include "dns.h"

#define QUERY_MAXLEVEL 4
#define QUERY_MAXALIAS 4
#define QUERY_MAXNS 16

struct query {
  unsigned int loop;
  unsigned int level;
  char *name[QUERY_MAXLEVEL];
  char *control[QUERY_MAXLEVEL]; /* pointing inside name */
  char *ns[QUERY_MAXLEVEL][QUERY_MAXNS];
  char servers[QUERY_MAXLEVEL][64];
  char *alias[QUERY_MAXALIAS];
  char localip[4];
  char type[2];
  struct dns_transmit dt;
} ;

extern int query_start(struct query *,char *,char *,char *);
extern void query_io(struct query *,iopause_fd *,struct taia *);
extern int query_get(struct query *,iopause_fd *,struct taia *);

#endif
