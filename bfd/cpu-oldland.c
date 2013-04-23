#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

const bfd_arch_info_type bfd_oldland_arch =
  {
    32,               /* 32 bits in a word.  */
    32,               /* 32 bits in an address.  */
    8,                /*  8 bits in a byte.  */
    bfd_arch_oldland,   /* enum bfd_architecture arch.  */
    bfd_mach_oldland,
    "oldland",          /* Arch name.  */
    "oldland",          /* Printable name.  */
    2,                /* Unsigned int section alignment power.  */
    TRUE,             /* The one and only.  */
    bfd_default_compatible,
    bfd_default_scan,
    bfd_arch_default_fill,
    0,
  };
