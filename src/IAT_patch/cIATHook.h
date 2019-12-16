#pragma once
#include <Windows.h>
#include <dbghelp.h>
#include <map>
#include <string>
#include <memory>
#include <stdexcept>
#include <algorithm>
#include <psapi.h>


#pragma comment(lib, "Dbghelp.lib")

typedef unsigned long long uint64_t;

class cIATHook {
public:
	cIATHook(char* szTargetModuleName, char* szFunction, PVOID hook);
	cIATHook(char* szFunction, PVOID pFunction, PVOID hook);
	~cIATHook();
	PROC hook_get_trampoline_end();
	BOOL PatchIAT();
	BOOL RestoreIAT();
private:
	__inline BOOL case_insensitive_match(std::string& a, std::string& b) const;
	PVOID _module_base, _hook_func;
	PROC  _original_function;
	PROC* _function_storage;
	char* _module_name;
	char* _function_name;
	bool  _search_for_module;
};