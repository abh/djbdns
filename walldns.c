#include "byte.h"
#include "dns.h"
#include "dd.h"
#include "response.h"

const char *fatal = "walldns: fatal: ";
const char *starting = "starting walldns\n";

void initialize(void)
{
  ;
}

int respond(char *q,char qtype[2])
{
  int flaga;
  int flagptr;
  char ip[4];
  int j;

  flaga = byte_equal(qtype,2,DNS_T_A);
  flagptr = byte_equal(qtype,2,DNS_T_PTR);
  if (byte_equal(qtype,2,DNS_T_ANY)) flaga = flagptr = 1;

  if (flaga || flagptr) {
    if (dd(q,"",ip) == 4) {
      if (flaga) {
        if (!response_rstart(q,DNS_T_A,655360)) return 0;
        if (!response_addbytes(ip,4)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
    j = dd(q,"\7in-addr\4arpa",ip);
    if (j >= 0) {
      if (flaga && (j == 4)) {
        if (!response_rstart(q,DNS_T_A,655360)) return 0;
        if (!response_addbytes(ip + 3,1)) return 0;
        if (!response_addbytes(ip + 2,1)) return 0;
        if (!response_addbytes(ip + 1,1)) return 0;
        if (!response_addbytes(ip + 0,1)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      if (flagptr) {
        if (!response_rstart(q,DNS_T_PTR,655360)) return 0;
        if (!response_addname(q)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
  }

  response[2] &= ~4;
  response[3] &= ~15;
  response[3] |= 5;
  return 1;
}
