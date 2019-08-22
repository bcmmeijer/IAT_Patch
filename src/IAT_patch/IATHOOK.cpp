#include "IATHOOK.h"

IATHOOK::IATHOOK(PVOID pModuleBase, char* szTargetModuleName, char* szFunction, PVOID targetFunction):	
	_module_base(pModuleBase), 
	_module_name(szTargetModuleName),
	_hook_func(targetFunction),
	_function_name(szFunction)
{}

IATHOOK::~IATHOOK()
{
	RestoreIAT();
}

BOOL IATHOOK::PatchIAT()
{
	ULONG size;
	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(this->_module_base, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);
	if (!importDir)
		return FALSE;
	PVOID orininalFunction = GetProcAddress(GetModuleHandle(this->_module_name), this->_function_name);
	if (!orininalFunction)
		return FALSE;

	while (importDir->Name) {
		char* moduleName = (char*)((uint64_t)this->_module_base + importDir->Name);
		if (strcmp(moduleName, this->_module_name) == 0) {
			PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((uint64_t)this->_module_base + importDir->FirstThunk);
			if (pIAT) {
				while (pIAT->u1.Function) {
					PROC* funcStorage = (PROC*)& pIAT->u1.Function;
					if (*funcStorage == orininalFunction) {
						MEMORY_BASIC_INFORMATION meminfo;
						VirtualQuery(funcStorage, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));
						if (!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
							return FALSE;
						this->_original_function = *funcStorage;
						*funcStorage = (PROC)this->_hook_func;
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

BOOL IATHOOK::RestoreIAT()
{
	ULONG size;
	PIMAGE_IMPORT_DESCRIPTOR importDir = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(this->_module_base, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);
	if (!importDir)
		return FALSE;
	while (importDir->Name) {
		char* moduleName = (char*)((uint64_t)this->_module_base + importDir->Name);
		if (strcmp(moduleName, this->_module_name) == 0) {
			PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((uint64_t)this->_module_base + importDir->FirstThunk);
			if (pIAT) {
				while (pIAT->u1.Function) {
					PROC* funcStorage = (PROC*)& pIAT->u1.Function;
					if (*funcStorage == this->_hook_func) {
						MEMORY_BASIC_INFORMATION meminfo;
						VirtualQuery(funcStorage, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));
						if (!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
							return FALSE;
						*funcStorage = (PROC)this->_original_function;
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
