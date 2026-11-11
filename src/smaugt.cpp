#include "registry.hpp"

extern "C" {

KPQC_DECLARE_KEM(smaugt128);
KPQC_DECLARE_KEM(smaugt192);
KPQC_DECLARE_KEM(smaugt256);
KPQC_DECLARE_KEM(timer);

}

namespace kpqc::smaugt {

KPQC_DEFINE_KEM(smaugt128, "SMAUG-T128", 672, 832, 672, 32)
KPQC_DEFINE_KEM(smaugt192, "SMAUG-T192", 1088, 1312, 992, 32)
KPQC_DEFINE_KEM(smaugt256, "SMAUG-T256", 1440, 1728, 1376, 32)
KPQC_DEFINE_KEM(timer, "TiMER", 672, 832, 608, 32)

}  // namespace kpqc::smaugt
