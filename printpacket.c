#include "uint16.h"
#include "uint32.h"
#include "error.h"
#include "byte.h"
#include "dns.h"
#include "printrecord.h"
#include "printpacket.h"

static char *d;

#define X(s) if (!stralloc_cats(out,s)) return 0;
#define NUM(u) if (!stralloc_catulong0(out,u,0)) return 0;

unsigned int printpacket_cat(stralloc *out,char *buf,unsigned int len)
{
  uint16 numqueries;
  uint16 numanswers;
  uint16 numauthority;
  uint16 numglue;
  unsigned int pos;
  char data[12];
  uint16 type;

  pos = dns_packet_copy(buf,len,0,data,12); if (!pos) return 0;

  uint16_unpack_big(data + 4,&numqueries);
  uint16_unpack_big(data + 6,&numanswers);
  uint16_unpack_big(data + 8,&numauthority);
  uint16_unpack_big(data + 10,&numglue);

  NUM(len)
  X(" bytes, ")
  NUM(numqueries)
  X("+")
  NUM(numanswers)
  X("+")
  NUM(numauthority)
  X("+")
  NUM(numglue)
  X(" records")

  if (data[2] & 128) X(", response")
  if (data[2] & 120) X(", weird op")
  if (data[2] & 4) X(", authoritative")
  if (data[2] & 2) X(", truncated")
  if (data[2] & 1) X(", weird rd")
  if (data[3] & 128) X(", weird ra")
  switch(data[3] & 15) {
    case 0: X(", noerror"); break;
    case 3: X(", nxdomain"); break;
    case 4: X(", notimp"); break;
    case 5: X(", refused"); break;
    default: X(", weird rcode");
  }
  if (data[3] & 112) X(", weird z")

  X("\n")

  while (numqueries) {
    --numqueries;
    X("query: ")

    pos = dns_packet_getname(buf,len,pos,&d); if (!pos) return 0;
    pos = dns_packet_copy(buf,len,pos,data,4); if (!pos) return 0;

    if (byte_diff(data + 2,2,DNS_C_IN)) {
      X("weird class")
    }
    else {
      uint16_unpack_big(data,&type);
      NUM(type)
      X(" ")
      if (!dns_domain_todot_cat(out,d)) return 0;
    }
    X("\n")
  }

  for (;;) {
    if (numanswers) { --numanswers; X("answer: ") }
    else if (numauthority) { --numauthority; X("authority: ") }
    else if (numglue) { --numglue; X("additional: ") }
    else break;

    pos = printrecord_cat(out,buf,len,pos,0,0);
    if (!pos) return 0;
  }

  if (pos != len) { errno = error_proto; return 0; }
  return 1;
}
