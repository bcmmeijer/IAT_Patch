#pragma once
#include <Windows.h>
#include <dbghelp.h>
#pragma comment(lib, "Dbghelp.lib")

typedef unsigned long long uint64_t;

class IATHOOK
{
public:
	IATHOOK(PVOID pModuleBase, char* szTargetModuleName, char* szFunction, PVOID targetFunction);
	~IATHOOK();
	BOOL PatchIAT();
	BOOL RestoreIAT();
private:
	PVOID		_module_base;
	PVOID		_hook_func;
	PROC		_original_function;
	uint64_t	_func_offset;
	char*		_module_name;
	char*		_function_name;
};

