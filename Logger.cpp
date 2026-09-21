#include "Logger.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace
{
    HANDLE g_logFile = INVALID_HANDLE_VALUE;

    void WriteRaw(const char* text, DWORD length)
    {
        if (g_logFile == INVALID_HANDLE_VALUE ||
            text == nullptr ||
            length == 0)
        {
            return;
        }

        DWORD written = 0;
        WriteFile(
            g_logFile,
            text,
            length,
            &written,
            nullptr);
    }
}

bool Logger::Initialize(
    const char* filePath,
    bool truncate)
{
    if (g_logFile != INVALID_HANDLE_VALUE)
        return true;

    const DWORD creationDisposition =
        truncate ? CREATE_ALWAYS : OPEN_ALWAYS;

    g_logFile = CreateFileA(
        filePath,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        creationDisposition,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
        nullptr);

    return g_logFile != INVALID_HANDLE_VALUE;
}

void Logger::Shutdown()
{
    if (g_logFile == INVALID_HANDLE_VALUE)
        return;

    FlushFileBuffers(g_logFile);
    CloseHandle(g_logFile);
    g_logFile = INVALID_HANDLE_VALUE;
}

void Logger::Write(const char* text)
{
    if (text == nullptr)
        return;

    WriteRaw(
        text,
        static_cast<DWORD>(strlen(text)));
}

void Logger::WriteLine(const char* text)
{
    Write(text);
    WriteRaw("\r\n", 2);
}

void Logger::Format(const char* format, ...)
{
    if (format == nullptr)
        return;

    char buffer[2048] = {};

    va_list args;
    va_start(args, format);
    std::vsnprintf(
        buffer,
        sizeof(buffer),
        format,
        args);
    buffer[sizeof(buffer) - 1] = '\0';
    va_end(args);

    WriteLine(buffer);
}

void Logger::Flush()
{
    if (g_logFile != INVALID_HANDLE_VALUE)
        FlushFileBuffers(g_logFile);
}
