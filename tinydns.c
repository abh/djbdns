#include "dns.h"

const char *fatal = "tinydns: fatal: ";

static char seed[128];

void initialize(void)
{
  dns_random_init(seed);
}
