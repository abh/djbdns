#ifndef LOG_H
#define LOG_H

#include "uint64.h"

extern void log_startup(void);

extern void log_query(unsigned int,char *,unsigned int,char *,char *,char *);
extern void log_querydrop(unsigned int);
extern void log_querydone(unsigned int,unsigned int);

extern void log_conn(unsigned int,char *,unsigned int);
extern void log_conndrop(unsigned int);

extern void log_cachedanswer(char *,char *);
extern void log_cachedcname(char *,char *);
extern void log_cachednxdomain(char *);
extern void log_cachedservfail(char *);
extern void log_cachedns(char *,char *);

extern void log_tx(char *,char *,char *,char *,unsigned int);

extern void log_nxdomain(char *,char *,unsigned int);
extern void log_nodata(char *,char *,char *,unsigned int);
extern void log_servfail(char *);
extern void log_lame(char *,char *,char *);

extern void log_rr(char *,char *,char *,char *,unsigned int,unsigned int);
extern void log_rrns(char *,char *,char *,unsigned int);
extern void log_rrcname(char *,char *,char *,unsigned int);
extern void log_rrptr(char *,char *,char *,unsigned int);
extern void log_rrmx(char *,char *,char *,char *,unsigned int);
extern void log_rrsoa(char *,char *,char *,char *,char *,unsigned int);

extern void log_stats(uint64 *,uint64 *);

#endif
