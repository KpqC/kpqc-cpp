#include "registry.hpp"

extern "C" {

KPQC_DECLARE_KEM(ntruplus768);
KPQC_DECLARE_KEM(ntruplus864);
KPQC_DECLARE_KEM(ntruplus1152);

}

namespace kpqc::ntruplus {

KPQC_DEFINE_KEM(ntruplus768, "NTRU+768", 1152, 2336, 1152, 32)
KPQC_DEFINE_KEM(ntruplus864, "NTRU+864", 1296, 2624, 1296, 32)
KPQC_DEFINE_KEM(ntruplus1152, "NTRU+1152", 1728, 3488, 1728, 32)

}  // namespace kpqc::ntruplus
