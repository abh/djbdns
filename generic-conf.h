#ifndef GENERIC_CONF_H
#define GENERIC_CONF_H

#include "buffer.h"

extern void init(char *,char *);

extern void makedir(char *);

extern void start(char *);
extern void outs(char *);
extern void out(char *,unsigned int);
extern void copyfrom(buffer *);
extern void finish(void);

extern void perm(int);
extern void owner(int,int);
extern void makelog(char *,int,int);

#endif
