#pragma once

#ifndef PCH_H
#define PCH_H

//DMA
#include "vmmdll.h"

#include <Windows.h>
#include <cstdio>
#include <sstream>
#include <fstream>
#include <filesystem>

#define DEBUG_INFO
#ifdef DEBUG_INFO
#define LOG(fmt, ...) std::printf(fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) std::wprintf(fmt, ##__VA_ARGS__)
#else
#define LOG
#define LOGW
#endif

#define THROW_EXCEPTION
#ifdef THROW_EXCEPTION
#define THROW(fmt, ...) throw std::runtime_error(fmt, ##__VA_ARGS__)
#endif

#endif //PCH_H

//#include "InputManager.h"
//#include "Registry.h"
#include "Shellcode.h"
#include "structs.h"
#include <winternl.h>

//#include <winnt.h>

enum class e_registry_type
{
    none = REG_NONE,
    sz = REG_SZ,
    expand_sz = REG_EXPAND_SZ,
    binary = REG_BINARY,
    dword = REG_DWORD,
    dword_little_endian = REG_DWORD_LITTLE_ENDIAN,
    dword_big_endian = REG_DWORD_BIG_ENDIAN,
    link = REG_LINK,
    multi_sz = REG_MULTI_SZ,
    resource_list = REG_RESOURCE_LIST,
    full_resource_descriptor = REG_FULL_RESOURCE_DESCRIPTOR,
    resource_requirements_list = REG_RESOURCE_REQUIREMENTS_LIST,
    qword = REG_QWORD,
    qword_little_endian = REG_QWORD_LITTLE_ENDIAN
};

class c_registry
{
private:
public:
    c_registry()
    {
    }

    ~c_registry()
    {
    }

    std::string QueryValue(const char* path, e_registry_type type);
};

class c_keys
{
private:
    uint64_t gafAsyncKeyStateExport = 0;
    uint8_t state_bitmap[64]{ };
    uint8_t previous_state_bitmap[256 / 8]{ };
    uint64_t win32kbase = 0;

    int win_logon_pid = 0;

    c_registry registry;
    std::chrono::time_point<std::chrono::system_clock> start = std::chrono::system_clock::now();

public:
    c_keys() = default;

    ~c_keys() = default;

    bool InitKeyboard();

    void UpdateKeys();
    bool IsKeyDown(uint32_t virtual_key_code);
};

class Memory
{
private:
    struct LibModules
    {
        HMODULE VMM = nullptr;
        HMODULE FTD3XX = nullptr;
        HMODULE LEECHCORE = nullptr;
    };

    static inline LibModules modules{ };

    struct CurrentProcessInformation
    {
        int PID = 0;
        size_t base_address = 0;
        size_t base_size = 0;
        std::string process_name = "";
    };

    static inline CurrentProcessInformation current_process{ };

    static inline BOOLEAN DMA_INITIALIZED = FALSE;
    static inline BOOLEAN PROCESS_INITIALIZED = FALSE;

    bool DumpMemoryMap(bool debug = false);
    bool SetFPGA();

    std::shared_ptr<c_keys> key;
    c_registry registry;

public:
    uintptr_t base = 0;

    bool InitMemory();
    c_registry GetRegistry() { return registry; }
    c_keys* GetKeyboard() { return key.get(); }
    bool Init(std::string process_name, bool memMap = true, bool debug = false);
    DWORD GetPidFromName(std::string process_name);
    std::vector<int> GetPidListFromName(std::string process_name);
    std::vector<std::string> GetModuleList(std::string process_name);
    VMMDLL_PROCESS_INFORMATION GetProcessInformation();
    PEB GetProcessPeb();
    size_t GetBaseDaddy(std::string module_name);
    size_t GetBaseSize(std::string module_name);
    uintptr_t GetExportTableAddress(std::string import, std::string process, std::string module);
    uintptr_t GetImportTableAddress(std::string import, std::string process, std::string module);
    bool FixCr3();
    bool DumpMemory(uintptr_t address, std::string path);
    uint64_t FindSignature(const char* signature, uint64_t range_start, uint64_t range_end, int PID = 0);
    bool write(uintptr_t address, void* buffer, size_t size) const;
    bool write(uintptr_t address, void* buffer, size_t size, int pid) const;

    template <typename T>
    void write(void* address, T value)
    {
        write(address, &value, sizeof(T));
    }

    template <typename T>
    void write(uintptr_t address, T value)
    {
        write(address, &value, sizeof(T));
    }

    bool read(uintptr_t address, void* buffer, size_t size) const;
    bool read_mem(uintptr_t address, void* buffer, size_t size) const;
    bool read(uintptr_t address, void* buffer, size_t size, int pid) const;

    template <typename T>
    T read(void* address)
    {
        T buffer{ };
        memset(&buffer, 0, sizeof(T));
        read(reinterpret_cast<uint64_t>(address), reinterpret_cast<void*>(&buffer), sizeof(T));

        return buffer;
    }

    template <typename T>
    T read(uint64_t address)
    {
        return read<T>(reinterpret_cast<void*>(address));
    }

    template <typename T>
    T read(void* address, int pid)
    {
        T buffer{ };
        memset(&buffer, 0, sizeof(T));
        read(reinterpret_cast<uint64_t>(address), reinterpret_cast<void*>(&buffer), sizeof(T), pid);

        return buffer;
    }

    template <typename T>
    T read(uint64_t address, int pid)
    {
        return read<T>(reinterpret_cast<void*>(address), pid);
    }

    uint64_t ReadChain(uint64_t base, const std::vector<uint64_t>& offsets)
    {
        uint64_t result = read<uint64_t>(base + offsets.at(0));
        for (int i = 1; i < offsets.size(); i++) result = read<uint64_t>(result + offsets.at(i));
        return result;
    }

    VMMDLL_SCATTER_HANDLE CreateScatterHandle() const;
    VMMDLL_SCATTER_HANDLE CreateScatterHandle(int pid) const;
    void CloseScatterHandle(VMMDLL_SCATTER_HANDLE handle);
    void AddScatterReadRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size);
    void AddScatterWriteRequest(VMMDLL_SCATTER_HANDLE handle, uint64_t address, void* buffer, size_t size);
    void ExecuteReadScatter(VMMDLL_SCATTER_HANDLE handle, int pid = 0);
    void ExecuteWriteScatter(VMMDLL_SCATTER_HANDLE handle, int pid = 0);

    VMM_HANDLE vHandle;
};

inline Memory* driver = new Memory;