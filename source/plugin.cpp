#include "plugin.h"


MiseryNodeAI g_WMiseryNodeAI;


EXPOSE_SINGLE_INTERFACE_GLOBALVAR(MiseryNodeAI, IServerPluginCallbacks, INTERFACEVERSION_ISERVERPLUGINCALLBACKS, g_WMiseryNodeAI);

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

bool MiseryNodeAI::FindMaxNodeSignature()
{
   
    HMODULE hModule = GetModuleHandleA("server.dll");
    if (!hModule) {
        printf("[MiseryNodeAI] impossible to locate server.dll\n");
        return false;
    }

    
    printf("[MiseryNodeAI] base server.dll adress: %p\n", (void*)hModule);

   
    const uintptr_t comparisonOffsets[] = {
        0x2692BE, // cmp dword ptr [rbx+8], 1000h
        0x26FF3E  // cmp eax, 1000h
    };

    
    const uintptr_t memAllocOffset = 0x2692AE; // mov ecx, 8000h

    
    m_MaxNodesCompareAddresses.clear(); 

   
    const int BYTES_TO_DISPLAY = 16; 

   
    for (size_t i = 0; i < sizeof(comparisonOffsets) / sizeof(comparisonOffsets[0]); i++) {
        uintptr_t address = (uintptr_t)hModule + comparisonOffsets[i];
        m_MaxNodesCompareAddresses.push_back(address);

        printf("[MiseryNodeAI] compare adress MAX_NODES %zu: %p (Offset: 0x%X)\n",
            i + 1, (void*)address, (unsigned int)comparisonOffsets[i]);

        
        printf("[MiseryNodeAI] memory content: ");
        for (int j = 0; j < BYTES_TO_DISPLAY; j++) {
            __try {
                printf("%02X ", *((unsigned char*)address + j));
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                printf("?? "); 
            }
        }
        printf("\n");
    }

    
    m_MemoryAllocationAddress = (uintptr_t)hModule + memAllocOffset;
    printf("[MiseryNodeAI] allocate memory adress: %p (Offset: 0x%X)\n",
        (void*)m_MemoryAllocationAddress, (unsigned int)memAllocOffset);

    
    printf("[MiseryNodeAI] memory content: ");
    for (int j = 0; j < BYTES_TO_DISPLAY; j++) {
        __try {
            printf("%02X ", *((unsigned char*)m_MemoryAllocationAddress + j));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("?? "); 
        }
    }
    printf("\n");

    
    return true;
}

bool MiseryNodeAI::IncreaseMaxNodes(uint32_t newMaxNodes)
{
    if (m_MaxNodesCompareAddresses.empty() || m_MemoryAllocationAddress == 0) {
        printf("[MiseryNodeAI] MAX_NODES adresses not found. call first FindMaxNodeSignature()\n");
        return false;
    }

    
    const uint32_t OLD_MAX_NODES = 0x1000;
    const uint32_t NEW_MAX_NODES_VALUE = 0x2000;
    const uint32_t OLD_ALLOCATION = 0x8000;
    const uint32_t NEW_ALLOCATION = 0x10000;

    bool success = false;
    int patchCount = 0;

  
    for (size_t i = 0; i < m_MaxNodesCompareAddresses.size(); i++) {
        uintptr_t address = m_MaxNodesCompareAddresses[i];

       
        for (int offset = -8; offset < 8; offset++) {
            __try {
                uint32_t* valuePtr = (uint32_t*)(address + offset);
                if (*valuePtr == OLD_MAX_NODES) {
                    printf("[MiseryNodeAI] found value 0x%X at adress %p (decal %d)\n",
                        OLD_MAX_NODES, (void*)(address + offset), offset);

                    DWORD oldProtect;
                    if (VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), PAGE_READWRITE, &oldProtect)) {
                        
                        *valuePtr = NEW_MAX_NODES_VALUE;

                       
                        if (*valuePtr == NEW_MAX_NODES_VALUE) {
                            printf("[MiseryNodeAI] success value edited: 0x%X -> 0x%X\n",
                                OLD_MAX_NODES, NEW_MAX_NODES_VALUE);
                            success = true;
                            patchCount++;
                        }
                        else {
                            printf("[MiseryNodeAI] failed to edit\n");
                        }

                        
                        DWORD dummy;
                        VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), oldProtect, &dummy);
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                
            }
        }
    }

    
    for (int offset = -8; offset < 8; offset++) {
        __try {
            uint32_t* valuePtr = (uint32_t*)(m_MemoryAllocationAddress + offset);
            if (*valuePtr == OLD_ALLOCATION) {
                printf("[MiseryNodeAI] found value 0x%X at adress %p (decal %d)\n",
                    OLD_ALLOCATION, (void*)(m_MemoryAllocationAddress + offset), offset);

                DWORD oldProtect;
                if (VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), PAGE_READWRITE, &oldProtect)) {
                   
                    *valuePtr = NEW_ALLOCATION;

                    
                    if (*valuePtr == NEW_ALLOCATION) {
                        printf("[MiseryNodeAI] allocated value edited with success: 0x%X -> 0x%X\n",
                            OLD_ALLOCATION, NEW_ALLOCATION);
                        success = true;
                        patchCount++;
                    }
                    else {
                        printf("[MiseryNodeAI] failed x2\n");
                    }

                    
                    DWORD dummy;
                    VirtualProtect((LPVOID)valuePtr, sizeof(uint32_t), oldProtect, &dummy);
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            
        }
    }

    printf("[MiseryNodeAI] Patched module. %d value edited.\n", patchCount);
    return success;
}

bool MiseryNodeAI::PatchMaxNodes()
{
    printf("[MiseryNodeAI] try patching MAX_NODES...\n");
    fflush(stdout);

   
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)m_MaxNodesAddress, sizeof(uint32_t), PAGE_READWRITE, &oldProtect)) {
        DWORD error = GetLastError();
        printf("[MiseryNodeAI] VirtualProtect has failed! Code erreur: %lu\n", error);
        fflush(stdout);

        return false;
    }

    
    uint32_t oldValue = *(uint32_t*)m_MaxNodesAddress;
    printf("[MiseryNodeAI] actual value at adress %p: %u\n", (void*)m_MaxNodesAddress, oldValue);
    fflush(stdout);

  
    *(uint32_t*)m_MaxNodesAddress = NEW_MAX_NODES;

   
    uint32_t newValue = *(uint32_t*)m_MaxNodesAddress;
    printf("[MiseryNodeAI] New value after edit: %u\n", newValue);
    fflush(stdout);

    
    DWORD temp;
    VirtualProtect((LPVOID)m_MaxNodesAddress, sizeof(uint32_t), oldProtect, &temp);

    if (newValue == NEW_MAX_NODES) {
        printf("[MiseryNodeAI] MAX_NODES patched from %u to %u with success!\n", oldValue, newValue);
        fflush(stdout);
        return true;
    }
    else {
        printf("[MiseryNodeAI] patching fail! value has not been modified.\n");
        fflush(stdout);
        return false;
    }
}

bool MiseryNodeAI::Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory)
{
    printf("[MiseryNodeAI] Loading plugin...\n");
    fflush(stdout);

    
    m_pEngine = (IVEngineServer*)gameServerFactory(INTERFACEVERSION_VENGINESERVER, NULL);

   
    bool maxNodesPatchApplied = false;
    bool memAllocPatchApplied = false;


    HMODULE hModule = GetModuleHandleA("server.dll");
    if (hModule) {
   
    uintptr_t maxNodesCheckAddr1 = (uintptr_t)hModule + 0x2692BE; // cmp dword ptr [rbx+8], 0x2000
    uintptr_t maxNodesCheckAddr2 = (uintptr_t)hModule + 0x26FF3E; // cmp eax, 0x2000

    bool maxNodesPatchApplied = false;
    __try {
        uint8_t val1 = *(uint8_t*)maxNodesCheckAddr1;
        uint8_t val2 = *(uint8_t*)maxNodesCheckAddr2;
        if (val1 == 0x20 && val2 == 0x20) {
            printf("[MiseryNodeAI] MAX_NODES patch already applied (val1: 0x%X, val2: 0x%X).\n", val1, val2);
            maxNodesPatchApplied = true;
        } else {
            printf("[MiseryNodeAI] MAX_NODES patch not applied yet (val1: 0x%X, val2: 0x%X).\n", val1, val2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[MiseryNodeAI] Error while checking MAX_NODES patch status.\n");
    }

 
    uintptr_t memAllocCheckAddr = (uintptr_t)hModule + 0x2692AE; // mov ecx, 0x10000
    bool memAllocPatchApplied = false;
    __try {
        uint16_t allocVal = *(uint16_t*)memAllocCheckAddr;
        if (allocVal == 0x0100) { // 0x10000 little endian
            printf("[MiseryNodeAI] Memory allocation patch already applied (value: 0x%X).\n", allocVal);
            memAllocPatchApplied = true;
        } else {
            printf("[MiseryNodeAI] Memory allocation patch not applied yet (value: 0x%X).\n", allocVal);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[MiseryNodeAI] Error while checking memory allocation patch status.\n");
    }

    bool alreadyPatched = maxNodesPatchApplied && memAllocPatchApplied;

    if (!alreadyPatched) {
        if (!FindMaxNodeSignature()) {
            printf("[MiseryNodeAI] Impossible to find MAX_NODES signature, overpassing this step.\n");
            fflush(stdout);
        }
        else if (!IncreaseMaxNodes(NEW_MAX_NODES)) {
            printf("[MiseryNodeAI] failed to raise MAX_NODES at %u, overpassing this step.\n", NEW_MAX_NODES);
            fflush(stdout);
        }
        else {
            printf("[MiseryNodeAI] MAX_NODES raised to %u successfully!\n", NEW_MAX_NODES);
        }
    }
}

printf("[MiseryNodeAI] Plugin loaded successfully!\n");
fflush(stdout);
return true;
}

void MiseryNodeAI::LevelInit(char const* pMapName)
{


}

void MiseryNodeAI::Unload()
{
    printf("[MiseryNodeAI] Plugin unloaded!\n");
    fflush(stdout);
}

const char* MiseryNodeAI::GetPluginDescription()
{
    return " Misery Node AI - Raise Max Nodes for Garry's Mod";
}