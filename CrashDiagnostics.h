#pragma once

#include <cstdint>

namespace StaticBoundsLimitPatch
{
    bool Install();
    void Uninstall();

    bool IsInstalled();
    uint32_t ConfiguredLimit();
}
