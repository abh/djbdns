#include <unistd.h>
#include <pwd.h>
#include "strerr.h"
#include "exit.h"
#include "auto_home.h"
#include "generic-conf.h"

#define FATAL "axfrdns-conf: fatal: "

void usage(void)
{
  strerr_die1x(100,"axfrdns-conf: usage: axfrdns-conf acct logacct /axfrdns /tinydns myip");
}

char *dir;
char *user;
char *loguser;
struct passwd *pw;
char *myip;
char *tinydns;

int main(int argc,char **argv)
{
  user = argv[1];
  if (!user) usage();
  loguser = argv[2];
  if (!loguser) usage();
  dir = argv[3];
  if (!dir) usage();
  if (dir[0] != '/') usage();
  tinydns = argv[4];
  if (!tinydns) usage();
  if (tinydns[0] != '/') usage();
  myip = argv[5];
  if (!myip) usage();

  pw = getpwnam(loguser);
  if (!pw)
    strerr_die3x(111,FATAL,"unknown account ",loguser);

  init(dir,FATAL);
  makelog(loguser,pw->pw_uid,pw->pw_gid);

  makedir("env");
  perm(02755);
  start("env/ROOT"); outs(tinydns); outs("/root\n"); finish();
  perm(0644);
  start("env/IP"); outs(myip); outs("\n"); finish();
  perm(0644);

  start("run");
  outs("#!/bin/sh\nexec 2>&1\nexec envdir ./env sh -c '\n  exec envuidgid "); outs(user);
  outs(" softlimit -d300000 tcpserver -vDRHl0 -x tcp.cdb -- \"$IP\" 53 ");
  outs(auto_home); outs("/bin/axfrdns\n'\n");
  finish();
  perm(0755);

  start("Makefile");
  outs("tcp.cdb: tcp\n");
  outs("\ttcprules tcp.cdb tcp.tmp < tcp\n");
  finish();
  perm(0644);

  start("tcp");
  outs("# sample line:  1.2.3.4:allow,AXFR=\"heaven.af.mil/3.2.1.in-addr.arpa\"\n");
  outs(":deny\n");
  finish();
  perm(0644);

  _exit(0);
}
