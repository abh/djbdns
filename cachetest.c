#include "buffer.h"
#include "exit.h"
#include "cache.h"
#include "str.h"

main(int argc,char **argv)
{
  int i;
  char *x;
  char *y;
  unsigned int u;

  if (!cache_init(200)) _exit(111);

  if (*argv) ++argv;

  while (x = *argv++) {
    i = str_chr(x,':');
    if (x[i])
      cache_set(x,i,x + i + 1,str_len(x) - i - 1,86400);
    else {
      y = cache_get(x,i,&u);
      if (y)
        buffer_put(buffer_1,y,u);
      buffer_puts(buffer_1,"\n");
    }
  }

  buffer_flush(buffer_1);
  _exit(0);
}
