#include "buffer.h"
#include "qlog.h"

static void put(char c)
{
  buffer_put(buffer_2,&c,1);
}

static void hex(unsigned char c)
{
  put("0123456789abcdef"[(c >> 4) & 15]);
  put("0123456789abcdef"[c & 15]);
}

static void octal(unsigned char c)
{
  put('\\');
  put('0' + ((c >> 6) & 7));
  put('0' + ((c >> 3) & 7));
  put('0' + (c & 7));
}

void qlog(const char ip[4],uint16 port,const char id[2],const char *q,const char qtype[2],const char *result)
{
  char ch;
  char ch2;

  hex(ip[0]);
  hex(ip[1]);
  hex(ip[2]);
  hex(ip[3]);
  put(':');
  hex(port >> 8);
  hex(port & 255);
  put(':');
  hex(id[0]);
  hex(id[1]);
  buffer_puts(buffer_2,result);
  hex(qtype[0]);
  hex(qtype[1]);
  put(' ');

  if (!*q)
    put('.');
  else
    for (;;) {
      ch = *q++;
      while (ch--) {
        ch2 = *q++;
        if ((ch2 >= 'A') && (ch2 <= 'Z'))
	  ch2 += 32;
        if (((ch2 >= 'a') && (ch2 <= 'z')) || ((ch2 >= '0') && (ch2 <= '9')) || (ch2 == '-') || (ch2 == '_'))
	  put(ch2);
        else
	  octal(ch2);
      }
      if (!*q) break;
      put('.');
    }

  put('\n');
  buffer_flush(buffer_2);
}
