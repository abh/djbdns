#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "ip4.h"
#include "okclient.h"

static char fn[3 + IP4_FMT];

int okclient(char ip[4])
{
  struct stat st;
  int i;

  fn[0] = 'i';
  fn[1] = 'p';
  fn[2] = '/';
  fn[3 + ip4_fmt(fn + 3,ip)] = 0;

  for (;;) {
    if (stat(fn,&st) == 0) return 1;
    /* treat temporary error as rejection */
    i = str_rchr(fn,'.');
    if (!fn[i]) return 0;
    fn[i] = 0;
  }
}
