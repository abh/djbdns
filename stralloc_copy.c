#include "byte.h"
#include "stralloc.h"

int stralloc_copy(stralloc *sato,stralloc *safrom)
{
  return stralloc_copyb(sato,safrom->s,safrom->len);
}
