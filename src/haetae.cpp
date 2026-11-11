#include "registry.hpp"

extern "C" {

KPQC_DECLARE_SIGNATURE(haetae2);
KPQC_DECLARE_SIGNATURE(haetae3);
KPQC_DECLARE_SIGNATURE(haetae5);

}

namespace kpqc::haetae {

KPQC_DEFINE_SIGNATURE(haetae2, "haetae-mode2", 992, 1408, 1474)
KPQC_DEFINE_SIGNATURE(haetae3, "haetae-mode3", 1472, 2112, 2349)
KPQC_DEFINE_SIGNATURE(haetae5, "haetae-mode5", 2080, 2752, 2948)

}  // namespace kpqc::haetae
