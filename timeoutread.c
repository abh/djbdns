#include <unistd.h>
#include "error.h"
#include "iopause.h"
#include "timeoutread.h"

int timeoutread(int t,int fd,char *buf,int len)
{
  struct taia now;
  struct taia deadline;
  iopause_fd x;

  taia_now(&now);
  taia_uint(&deadline,t);
  taia_add(&deadline,&now,&deadline);

  x.fd = fd;
  x.events = IOPAUSE_READ;
  for (;;) {
    taia_now(&now);
    iopause(&x,1,&deadline,&now);
    if (x.revents) break;
    if (taia_less(&deadline,&now)) {
      errno = error_timeout;
      return -1;
    }
  }
  return read(fd,buf,len);
}
