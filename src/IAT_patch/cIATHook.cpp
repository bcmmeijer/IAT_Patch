#include "cIATHook.h"

cIATHook::cIATHook(char* szTargetModuleName, char* szFunction, PVOID hook) :
	_module_base(NULL),
	_module_name(szTargetModuleName),
	_hook_func(hook),
	_function_name(szFunction) 
{
	_module_base = GetModuleHandle(NULL);
	this->PatchIAT();
}

cIATHook::cIATHook(char* szFunction, PVOID pFunction, PVOID hook) :
	_module_base(NULL),
	_module_name(NULL),
	_hook_func(hook),
	_function_name(szFunction),
	_search_for_module(true)
{
	this->_module_name = new char[260];
	HMODULE hModule = NULL;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)pFunction, &hModule);
	if (hModule == INVALID_HANDLE_VALUE)
		throw std::runtime_error("Cannot get module handle from function address");
	size_t size = GetModuleBaseNameA(GetCurrentProcess(), hModule, _module_name, 260);
	if (!size)
		throw std::runtime_error("Could not get module name from handle");
}



cIATHook::~cIATHook() {
	if (_search_for_module)
		delete[] _module_name;
	RestoreIAT();
}

PROC cIATHook::hook_get_trampoline_end() {
	return this->_original_function;
}

BOOL cIATHook::PatchIAT() {

	HMODULE						hModule = GetModuleHandle(NULL);
	LONG						baseAddress = (LONG)hModule;
	BOOL						found = FALSE;
	ULONG						size;
	PIMAGE_IMPORT_DESCRIPTOR	pIID;
	PIMAGE_THUNK_DATA			pILT, pFirstThunkTest;
	std::string					a, b;
	DWORD						dwOld;

	//Get image import directory
	pIID = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToDataEx(this->_module_base, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size, NULL);
	if (!pIID)
		throw std::runtime_error("Could not get Image Directory");

	// Find module
	b = this->_module_name;
	while (pIID->Name) {

		a = (char*)((uint64_t)this->_module_base + pIID->Name);

		if (case_insensitive_match(a, b)) {
			found = TRUE;
			break;
		}

		pIID++;
	}

	if (!found)
		throw std::runtime_error("Could not find module");
	found = FALSE;

	// Search for function
	pILT = (PIMAGE_THUNK_DATA)((uint64_t)this->_module_base + pIID->OriginalFirstThunk);
	pFirstThunkTest = (PIMAGE_THUNK_DATA)(((uint64_t)this->_module_base + pIID->FirstThunk));

	while (!(pILT->u1.Ordinal & IMAGE_ORDINAL_FLAG) && pILT->u1.AddressOfData) {
		PIMAGE_IMPORT_BY_NAME pIIBM = (PIMAGE_IMPORT_BY_NAME)((uint64_t)this->_module_base + pILT->u1.AddressOfData);
		char* cur_func_name = (char*)(pIIBM->Name);
		if (!strcmp(_function_name, cur_func_name)) {
			found = TRUE;
			break;
		}
		pFirstThunkTest++;
		pILT++;
	}

	if (!found)
		throw std::runtime_error("Could not find function in module");

	dwOld = NULL;
#ifdef _WIN64
	if (!VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(uint64_t), PAGE_READWRITE, &dwOld))
		throw std::runtime_error("Could not get read+write access on memory region");

	//save original function address to be able to call later;
	_original_function = (PROC)pFirstThunkTest->u1.Function;

	//save address of table entry to easily restore original function pointer
	_function_storage = (PROC*)&pFirstThunkTest->u1.Function;

	//overwrite table entry with hook function
	pFirstThunkTest->u1.Function = (ULONGLONG)_hook_func;

	if (!VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(uint64_t), dwOld, &dwOld))
		throw std::runtime_error("Could not restore old protection on memory region");
#else
	if (!VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(DWORD), PAGE_READWRITE, &dwOld))
		throw std::runtime_error("Could not get read+write access on memory region");

	//save original function address to be able to call later;
	_original_function = (PROC)pFirstThunkTest->u1.Function;

	//save address of table entry to easily restore original function pointer
	_function_storage = (PROC*)&pFirstThunkTest->u1.Function;

	//overwrite table entry with hook function
	pFirstThunkTest->u1.Function = (DWORD)_hook_func;

	if (!VirtualProtect((LPVOID) & (pFirstThunkTest->u1.Function), sizeof(DWORD), dwOld, &dwOld))
		throw std::runtime_error("Could not restore old protection on memory region");
#endif

	return TRUE;
}

BOOL cIATHook::RestoreIAT() {

	MEMORY_BASIC_INFORMATION meminfo;
	VirtualQuery(_function_storage, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));

	if (!VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, PAGE_READWRITE, &meminfo.Protect))
		return FALSE;

	*_function_storage = _original_function;
	DWORD dwOldProtect;

	if (VirtualProtect(meminfo.BaseAddress, meminfo.RegionSize, meminfo.Protect, &dwOldProtect))
		return TRUE;

}

BOOL cIATHook::case_insensitive_match(std::string& a, std::string& b) const {
	std::transform(a.begin(), a.end(), a.begin(), ::tolower);
	std::transform(b.begin(), b.end(), b.begin(), ::tolower);
	return a.compare(b) == 0;
}
