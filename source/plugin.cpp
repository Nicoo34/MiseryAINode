#include "plugin.h"



MiseryNodeAI g_WMiseryNodeAI;

EXPOSE_SINGLE_INTERFACE_GLOBALVAR(MiseryNodeAI, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS, g_WMiseryNodeAI);


void PrintPatternHex(const char* pattern, const char* mask) {
    size_t len = strlen(mask);
    for (size_t i = 0; i < len; ++i) {
        printf("%02X", (unsigned char)pattern[i]);
        if (i < len - 1) printf(" ");
    }
}

uintptr_t MiseryNodeAI::FindPattern(uintptr_t base, size_t size, const char* pattern, const char* mask) {
    size_t patternLen = strlen(mask);
    for (size_t i = 0; i <= size - patternLen; i++) {
        bool found = true;
        for (size_t j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && pattern[j] != *((char*)base + i + j)) {
                found = false;
                break;
            }
        }
        if (found) return base + i;
    }
    return 0;
}

#ifdef _WIN32
uintptr_t GetModuleBase(const char* modName, size_t* moduleSize) {
    HMODULE hModule = GetModuleHandleA(modName);
    if (!hModule) return 0;
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO))) return 0;
    if (moduleSize) *moduleSize = (size_t)modInfo.SizeOfImage;
    return (uintptr_t)modInfo.lpBaseOfDll;
}
#endif

MiseryNodeAI::MiseryNodeAI()
{
    m_iClientCommandIndex = 0;
    m_pEngine = nullptr;
    m_pGameEventManager = nullptr;
    m_pNodeHook = nullptr;
    m_bHookInstalled = false;
    m_MaxNodesAddress = 0;
}

MiseryNodeAI::~MiseryNodeAI()
{
}

bool MiseryNodeAI::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory)
{
    printf("[MiseryNodeAI] Loading plugin...\n");
    fflush(stdout);

    m_pEngine = (IVEngineServer*)gameServerFactory(INTERFACEVERSION_VENGINESERVER, NULL);

    if (!FindMaxNodeSignature()) {
        printf("[MiseryNodeAI] can't find MAX_NODES SIGNATURES, patch not applied.\n");
        fflush(stdout);
    }
    else if (!IncreaseMaxNodes(NEW_MAX_NODES)) {
        printf("[MiseryNodeAI] MAX_NODES patch failed at %u.\n", NEW_MAX_NODES);
        fflush(stdout);
    }
    else {
        printf("[MiseryNodeAI] MAX_NODES raised at %u !\n", NEW_MAX_NODES);
    }

    printf("[MiseryNodeAI] Plugin loaded successfully!\n");
    fflush(stdout);
    return true;
}

bool MiseryNodeAI::FindMaxNodeSignature()
{
    size_t moduleSize = 0;
#ifdef _WIN32
    uintptr_t baseAddress = GetModuleBase("server.dll", &moduleSize);
#endif
    if (!baseAddress || !moduleSize) {
        printf("[MiseryNodeAI] server.dll not found\n");
        return false;
    }

    printf("[MiseryNodeAI] base %s address: %p, size: %zu\n",
#ifdef _WIN32
        "server.dll",
#endif
        (void*)baseAddress, moduleSize);

    struct PatchPattern {
        const char* pattern;
        const char* mask;
        int patchOffset;
    };

    std::vector<PatchPattern> patterns;

#ifdef _WIN32
    patterns = {
        // cmp dword ptr [rbx+8], 0x1000
        {"\x81\x7B\x08\x00\x10\x00\x00\x7C\x10\x48\x8D\x0D\xAE\xB4\x67\x00", "xxxxxxxxxxxxxxxx", 3},
        // cmp eax, 0x1000 
        {"\x3D\x00\x10\x00\x00\x0F\x87\x39\x09\x00\x00\x48\x8B\x0D\x0A\xAE", "xxxxxxxxxxxxxxx", 1},
        // mov ecx, 0x8000
        {"\xB9\x00\x80\x00\x00\xE8\x9A\x5A\x12\x00\x48\x89\x43\x10\x81\x7B", "xxxxxxxxxxxxxxxx", 1}
    };
#endif

    m_MaxNodesCompareAddresses.clear();

    for (const auto& p : patterns) {
        uintptr_t found = FindPattern(baseAddress, moduleSize, p.pattern, p.mask);
        if (found) {
            uintptr_t valueAddr = found + p.patchOffset;
            m_MaxNodesCompareAddresses.push_back(valueAddr);
            printf("[MiseryNodeAI] Found patchable value at %p (pattern: ", (void*)valueAddr);
            PrintPatternHex(p.pattern, p.mask);
            printf(", offset: %d)\n", p.patchOffset);
        }
    }

    if (m_MaxNodesCompareAddresses.empty()) {
        printf("[MiseryNodeAI] No patchable addresses found!\n");
        return false;
    }

    m_MemoryAllocationAddress = m_MaxNodesCompareAddresses.back();

    return true;
}

bool MiseryNodeAI::IncreaseMaxNodes(uint32_t newMaxNodes)
{
    if (m_MaxNodesCompareAddresses.empty() || m_MemoryAllocationAddress == 0) {
        printf("[MiseryNodeAI] MAX_NODES addresses not found. call first FindMaxNodeSignature()\n");
        return false;
    }

#ifdef _WIN32
    const uint32_t OLD_MAX_NODES = 0x1000;
    const uint32_t OLD_ALLOCATION = 0x8000;
#endif
    const uint32_t NEW_MAX_NODES_VALUE = newMaxNodes;
    const uint32_t NEW_ALLOCATION = 0x10000;

    bool success = false;
    int patchCount = 0;

    for (size_t i = 0; i < m_MaxNodesCompareAddresses.size() - 1; i++) {
        uintptr_t address = m_MaxNodesCompareAddresses[i];
#ifdef _WIN32
        __try {
            uint32_t* valuePtr = (uint32_t*)address;
            if (*valuePtr == OLD_MAX_NODES) {
                DWORD oldProtect;
                if (VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), PAGE_READWRITE, &oldProtect)) {
                    *valuePtr = NEW_MAX_NODES_VALUE;
                    if (*valuePtr == NEW_MAX_NODES_VALUE) {
                        printf("[MiseryNodeAI] Patched MAX_NODES value at %p: 0x%X -> 0x%X\n", (void*)address, OLD_MAX_NODES, NEW_MAX_NODES_VALUE);
                        patchCount++;
                        success = true;
                    }
                    DWORD dummy;
                    VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), oldProtect, &dummy);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif
    }

    uintptr_t allocAddress = m_MemoryAllocationAddress;
#ifdef _WIN32
    __try {
        uint32_t* valuePtr = (uint32_t*)allocAddress;
        if (*valuePtr == OLD_ALLOCATION) {
            DWORD oldProtect;
            if (VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), PAGE_READWRITE, &oldProtect)) {
                *valuePtr = NEW_ALLOCATION;
                if (*valuePtr == NEW_ALLOCATION) {
                    printf("[MiseryNodeAI] Patched allocation value at %p: 0x%X -> 0x%X\n", (void*)allocAddress, OLD_ALLOCATION, NEW_ALLOCATION);
                    patchCount++;
                    success = true;
                }
                DWORD dummy;
                VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), oldProtect, &dummy);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
#endif

    printf("[MiseryNodeAI] Patched module. %d value(s) edited.\n", patchCount);
    return success;
}

void MiseryNodeAI::LevelInit(char const* pMapName) {}
void MiseryNodeAI::Unload()
{
    printf("[MiseryNodeAI] Plugin unloaded!\n");
    fflush(stdout);
}
const char* MiseryNodeAI::GetPluginDescription()
{
    return "Misery Node AI - Raise Max Nodes for Garry's Mod";
}