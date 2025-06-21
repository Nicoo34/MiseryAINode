#ifndef PLUGIN_H
#define PLUGIN_H

#include <interface.h>
#include <eiface.h>
#include <igameevents.h>
#include <tier1/tier1.h>
#include <vector>
#include <stdio.h>
#include <stdint.h>
#include <Windows.h> 
#include <thread>
#include <atomic>



#define ORIGINAL_MAX_NODES 4096
#define NEW_MAX_NODES 8192

class MiseryNodeAI : public IServerPluginCallbacks
{
public:
    MiseryNodeAI();
    ~MiseryNodeAI();


    bool Load(CreateInterfaceFn interfaceFactory, CreateInterfaceFn gameServerFactory);
    void Unload();
    virtual void LevelInit(char const* pMapName);
    void Pause() {}
    void UnPause() {}
    const char* GetPluginDescription();
    void ServerActivate(edict_t* pEdictList, int edictCount, int clientMax) {}
    void GameFrame(bool simulating) {}
    void LevelShutdown() {}
    void ClientActive(edict_t* pEntity) {}
    void ClientDisconnect(edict_t* pEntity) {}
    void ClientPutInServer(edict_t* pEntity, char const* playername) {}
    void SetCommandClient(int index) {}
    void ClientSettingsChanged(edict_t* pEdict) {}
    PLUGIN_RESULT ClientConnect(bool* bAllowConnect, edict_t* pEntity, const char* pszName, const char* pszAddress, char* reject, int maxrejectlen) { return PLUGIN_CONTINUE; }
    PLUGIN_RESULT ClientCommand(edict_t* pEntity, const CCommand& args) { return PLUGIN_CONTINUE; }
    PLUGIN_RESULT NetworkIDValidated(const char* pszUserName, const char* pszNetworkID) { return PLUGIN_CONTINUE; }
    void OnQueryCvarValueFinished(QueryCvarCookie_t iCookie, edict_t* pPlayerEntity, EQueryCvarValueStatus eStatus, const char* pCvarName, const char* pCvarValue) {}
    void OnEdictAllocated(edict_t* edict) {}
    void OnEdictFreed(const edict_t* edict) {}


    bool FindMaxNodeSignature();
    bool PatchMaxNodes();
    bool IncreaseMaxNodes(uint32_t newMaxNodes);

private:
    int m_iClientCommandIndex;
    IVEngineServer* m_pEngine;
    IGameEventManager2* m_pGameEventManager;
    void* m_pNodeHook;
    bool m_bHookInstalled;
    long m_LastAinFileSize = 0;

    uintptr_t m_MaxNodesAddress;
    std::vector<uintptr_t> m_MaxNodesCompareAddresses; 
    uintptr_t m_MemoryAllocationAddress = 0;          
};

extern MiseryNodeAI g_WMiseryNodeAI;

#endif 