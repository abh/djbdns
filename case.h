#ifndef CASE_H
#define CASE_H

extern void case_lowers(char *);
extern void case_lowerb(char *,unsigned int);
extern int case_diffs(char *,char *);
extern int case_diffb(char *,unsigned int,char *);
extern int case_starts(char *,char *);
extern int case_startb(char *,unsigned int,char *);

#define case_equals(s,t) (!case_diffs((s),(t)))

#endif
