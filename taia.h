#ifndef TAIA_H
#define TAIA_H

#include "tai.h"

struct taia {
  struct tai sec;
  unsigned long nano; /* 0...999999999 */
  unsigned long atto; /* 0...999999999 */
} ;

extern void taia_tai(struct taia *,struct tai *);

extern void taia_now(struct taia *);

extern double taia_approx(struct taia *);
extern double taia_frac(struct taia *);

extern void taia_add(struct taia *,struct taia *,struct taia *);
extern void taia_sub(struct taia *,struct taia *,struct taia *);
extern void taia_half(struct taia *,struct taia *);
extern int taia_less(struct taia *,struct taia *);

#define TAIA_PACK 16
extern void taia_pack(char *,struct taia *);
extern void taia_unpack(char *,struct taia *);

#define TAIA_FMTFRAC 19
extern unsigned int taia_fmtfrac(char *,struct taia *);

extern void taia_uint(struct taia *,unsigned int);

#endif
