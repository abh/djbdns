#ifndef PRINTRECORD_H
#define PRINTRECORD_H

#include "stralloc.h"

extern unsigned int printrecord_cat(stralloc *,const char *,unsigned int,unsigned int,const char *,const char *);
extern unsigned int printrecord(stralloc *,const char *,unsigned int,unsigned int,const char *,const char *);

#endif
