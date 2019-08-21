#include <Windows.h>
#include <dbghelp.h>
#include <iostream>
#include <assert.h>
#pragma comment(lib, "Dbghelp.lib")

BOOL PatchIAT(PVOID pModuleBase, const char* szTargetModuleName, const char* szFunction, PVOID targetFunction);
int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);


int main() {
	
	if (PatchIAT(GetModuleHandle(NULL), "USER32.dll", "MessageBoxA", MyMessageBoxA)) {
		std::cout << "[+] Successfully patched IAT\n";
		MessageBoxA(NULL, "test", "test", MB_OK);
	}
	else
		std::cout << "[-] Could not patch IAT\n";
	return 0;
}

BOOL PatchIAT(PVOID pModuleBase, const char* szTargetModuleName, const char* szFunction, PVOID targetFunction) {
	ULONG size;
	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(pModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);
	if (!importDir)
		return FALSE;
	PVOID orininalFunction = GetProcAddress(GetModuleHandle(szTargetModuleName), szFunction);
	if (!orininalFunction)
		return FALSE;

	while (importDir->Name) {
		char* moduleName = (char*)((uint64_t)pModuleBase + importDir->Name);
		if (strcmp(moduleName, szTargetModuleName) == 0) {
			PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((uint64_t)pModuleBase + importDir->FirstThunk);
			if (pIAT) {
				while (pIAT->u1.Function) {
					PROC* funcStorage = (PROC*)&pIAT->u1.Function;
					if (*funcStorage == orininalFunction) {
						MEMORY_BASIC_INFORMATION meminfo;
						VirtualQuery(funcStorage, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));
						if (!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
							return FALSE;
						*funcStorage = (PROC)targetFunction;
						DWORD dwOldProtect;
						VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, meminfo.Protect, &dwOldProtect);
						return TRUE;
					}
					pIAT++;
				}
			}
		}
		importDir++;
	}
	return FALSE;
}

int MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	return MessageBoxW(NULL, L"hooked message", L"", MB_OK);
}