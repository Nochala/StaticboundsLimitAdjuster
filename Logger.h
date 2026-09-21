#pragma once

#include <Windows.h>

namespace Logger
{
    bool Initialize(
        const char* filePath,
        bool truncate = true);

    void Shutdown();
    void Write(const char* text);
    void WriteLine(const char* text);
    void Format(const char* format, ...);
    void Flush();
}
