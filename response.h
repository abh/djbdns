#ifndef RESPONSE_H
#define RESPONSE_H

extern char response[];
extern unsigned int response_len;

extern int response_query(char *,char *);
extern void response_nxdomain(void);
extern void response_servfail(void);
extern void response_id(char *);
extern void response_tc(void);

extern int response_addbytes(char *,unsigned int);
extern int response_addname(char *);
extern int response_rstart(char *,char *,char *);
extern void response_rfinish(int);

#define RESPONSE_ANSWER 6
#define RESPONSE_AUTHORITY 8
#define RESPONSE_ADDITIONAL 10

extern int response_cname(char *,char *);

#endif
