#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "strerr.h"
#include "buffer.h"
#include "open.h"
#include "generic-conf.h"

static const char *fatal;
static const char *dir;
static const char *fn;

static int fd;
static char buf[1024];
static buffer ss;

void init(const char *d,const char *f)
{
  dir = d;
  fatal = f;
  umask(022);
  if (mkdir(dir,0700) == -1)
    strerr_die4sys(111,fatal,"unable to create ",dir,": ");
  if (chmod(dir,03755) == -1)
    strerr_die4sys(111,fatal,"unable to set mode of ",dir,": ");
  if (chdir(dir) == -1)
    strerr_die4sys(111,fatal,"unable to switch to ",dir,": ");
}

void fail(void)
{
  strerr_die6sys(111,fatal,"unable to create ",dir,"/",fn,": ");
}

void makedir(const char *s)
{
  fn = s;
  if (mkdir(fn,0700) == -1) fail();
}

void start(const char *s)
{
  fn = s;
  fd = open_trunc(fn);
  if (fd == -1) fail();
  buffer_init(&ss,buffer_unixwrite,fd,buf,sizeof buf);
}

void outs(const char *s)
{
  if (buffer_puts(&ss,s) == -1) fail();
}

void out(const char *s,unsigned int len)
{
  if (buffer_put(&ss,s,len) == -1) fail();
}

void copyfrom(buffer *b)
{
  if (buffer_copy(&ss,b) < 0) fail();
}

void finish(void)
{
  if (buffer_flush(&ss) == -1) fail();
  if (fsync(fd) == -1) fail();
  close(fd);
}

void perm(int mode)
{
  if (chmod(fn,mode) == -1) fail();
}

void owner(int uid,int gid)
{
  if (chown(fn,uid,gid) == -1) fail();
}

void makelog(const char *user,int uid,int gid)
{
  makedir("log");
  perm(02755);
  makedir("log/main");
  owner(uid,gid);
  perm(02755);
  start("log/status");
  finish();
  owner(uid,gid);
  perm(0644);

  start("log/run");
  outs("#!/bin/sh\nexec");
  outs(" setuidgid "); outs(user);
  outs(" multilog t ./main\n");
  finish();
  perm(0755);
}
