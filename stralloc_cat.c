#include "byte.h"
#include "stralloc.h"

int stralloc_cat(stralloc *sato,stralloc *safrom)
{
  return stralloc_catb(sato,safrom->s,safrom->len);
}
