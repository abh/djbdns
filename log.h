#ifndef LOG_H
#define LOG_H

#include "uint64.h"

extern void log_startup(void);

extern void log_query(uint64 *,const char *,unsigned int,const char *,const char *,const char *);
extern void log_querydrop(uint64 *);
extern void log_querydone(uint64 *,unsigned int);

extern void log_tcpopen(const char *,unsigned int);
extern void log_tcpclose(const char *,unsigned int);

extern void log_cachedanswer(const char *,const char *);
extern void log_cachedcname(const char *,const char *);
extern void log_cachednxdomain(const char *);
extern void log_cachedns(const char *,const char *);

extern void log_tx(const char *,const char *,const char *,const char *,unsigned int);

extern void log_nxdomain(const char *,const char *,unsigned int);
extern void log_nodata(const char *,const char *,const char *,unsigned int);
extern void log_servfail(const char *);
extern void log_lame(const char *,const char *,const char *);

extern void log_rr(const char *,const char *,const char *,const char *,unsigned int,unsigned int);
extern void log_rrns(const char *,const char *,const char *,unsigned int);
extern void log_rrcname(const char *,const char *,const char *,unsigned int);
extern void log_rrptr(const char *,const char *,const char *,unsigned int);
extern void log_rrmx(const char *,const char *,const char *,const char *,unsigned int);
extern void log_rrsoa(const char *,const char *,const char *,const char *,const char *,unsigned int);

extern void log_stats(void);

#endif
