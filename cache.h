#ifndef CACHE_H
#define CACHE_H

#include "uint64.h"

extern uint64 cache_motion;
extern int cache_init(unsigned int);
extern void cache_set(char *,unsigned int,char *,unsigned int,unsigned int);
extern char *cache_get(char *,unsigned int,unsigned int *);

#endif
