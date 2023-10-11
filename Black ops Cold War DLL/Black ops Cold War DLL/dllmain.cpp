#include "pch.h"
#include <Windows.h>
#include <filesystem>
#include <ctime>
#include <vector>

struct LootItem {
    char pad[4];
    int itemId;
    int itemQuantity;
    int itemDate;
    char pad2[4];
};

struct StringTable {
    uintptr_t hash;
    int columnCount;
    int rowCount;
    char pad[40];
};

DWORD64 resolveRelativeAddress(DWORD64 instr, DWORD offset, DWORD instrSize) {
    return instr == 0ui64 ? 0ui64 : (instr + instrSize + *(int*)(instr + offset));
}

bool compareByte(const char* pData, const char* bMask, const char* szMask) {
    for (; *szMask; ++szMask, ++pData, ++bMask)
        if (*szMask == 'x' && *pData != *bMask)
            return false;
    return (*szMask) == NULL;
}

DWORD64 PatternScanEx(DWORD64 dwAddress, DWORD64 dwLen, const char* bMask, const char* szMask) {
    DWORD length = (DWORD)strlen(szMask);
    for (DWORD i = 0; i < dwLen - length; i++)
        if (compareByte((const char*)(dwAddress + i), bMask, szMask))
            return (DWORD64)(dwAddress + i);
    return 0ui64;
}

void UnlockAll() {
    uintptr_t base = (uintptr_t)(GetModuleHandle(0));

    uintptr_t stringtable_getValue = resolveRelativeAddress(PatternScanEx(base + 0x8400000, 0xA900000, "\xE8\x00\x00\x00\x00\x48\x8B\xCF\xFF\xC3", "x????xxxxx"), 1, 5);
    uintptr_t DB_FindXAssetHeader_ = resolveRelativeAddress(PatternScanEx(base + 0x7400000, 0x9600000, "\xE8\x00\x00\x00\x00\x3B\x78\x0C", "x????xxx"), 1, 5);
    uintptr_t GetItemQuantity = PatternScanEx(base + 0xA500000, 0xD300000, "\xE8\x00\x00\x00\x00\x48\x85\xC0\x74\x08\x8B\x40\x04", "x????xxxxxxxx");


    uintptr_t resolve = ((GetItemQuantity)+*(int*)((GetItemQuantity)+1) + 5);
    uintptr_t lootBase = ((resolve + 0x20) + *(int*)((resolve + 0x20) + 3) + 7);
    auto FindXAssetHeader = reinterpret_cast<uintptr_t(*)(int type, uintptr_t givenHash, bool errorIfMissing, int waitTime)>(DB_FindXAssetHeader_); // E8 ? ? ? ? 3B 78 0C call 
    auto StringTable_GetColumnValueForRow = reinterpret_cast<uintptr_t(*)(StringTable * table, char** out, int row, int column)>(stringtable_getValue); // E8 ? ? ? ? 48 8B CF FF C3 call

    char* out;
    std::vector<int>itemIds;
    uintptr_t lootTable = FindXAssetHeader(63, 0x411DEAF0BB60BA86, false, -1);
    if (lootTable) {
        auto table = reinterpret_cast<StringTable*>(lootTable);
        auto inventory = reinterpret_cast<LootItem*>(lootBase + 0x3B0);
        for (int row = 0; row < table->rowCount; ++row) {
            StringTable_GetColumnValueForRow(table, &out, row, 0);
            int cell = atoi(out);
            if (cell)
                itemIds.push_back(cell);
        }
        int time = std::time(0);
        int lootSize = itemIds.size();
        for (int y = 0; y < lootSize; ++y) {
            auto item = &inventory[y];
            item->itemId = itemIds[y];
            item->itemQuantity = 1;
            item->itemDate = time;
        }
        *(int*)(lootBase + 0x61E34) = lootSize;
        *(int*)(lootBase + 0x61E3C) = 1;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
        UnlockAll();
        break;
    }
    case DLL_PROCESS_DETACH: {
        break;
    }
    }
    return TRUE;
}