#include <sys/types.h>
#include <sys/time.h>
#include "scan.h"
#include "exit.h"

char *fn;

char *ustr;
unsigned long u;
time_t ut[2];

int main(int argc,char **argv)
{
  fn = argv[1];
  if (!fn) _exit(100);

  ustr = argv[2];
  if (!ustr) _exit(100);
  scan_ulong(ustr,&u);

  ut[0] = ut[1] = u;
  if (utime(fn,ut) == -1) _exit(111);
  _exit(0);
}
