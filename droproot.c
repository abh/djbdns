#include <unistd.h>
#include "env.h"
#include "scan.h"
#include "prot.h"
#include "strerr.h"

void droproot(const char *fatal)
{
  char *x;
  unsigned long id;

  x = env_get("ROOT");
  if (!x)
    strerr_die2x(111,fatal,"$ROOT not set");
  if (chdir(x) == -1)
    strerr_die4sys(111,fatal,"unable to chdir to ",x,": ");
  if (chroot(".") == -1)
    strerr_die4sys(111,fatal,"unable to chroot to ",x,": ");

  x = env_get("GID");
  if (!x)
    strerr_die2x(111,fatal,"$GID not set");
  scan_ulong(x,&id);
  if (prot_gid((int) id) == -1)
    strerr_die2sys(111,fatal,"unable to setgid: ");

  x = env_get("UID");
  if (!x)
    strerr_die2x(111,fatal,"$UID not set");
  scan_ulong(x,&id);
  if (prot_uid((int) id) == -1)
    strerr_die2sys(111,fatal,"unable to setuid: ");
}
