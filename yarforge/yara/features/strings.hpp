#pragma once

#include <string>
#include <unordered_set>
#include <vector>

namespace yarforge
{
	struct string_hash
	{
		using is_transparent = void;
		size_t operator()(std::string_view sv) const { return std::hash<std::string_view>{}(sv); }
	};

	inline const std::unordered_set<std::string, string_hash, std::equal_to<>> blocklist_exact(
		{
			"ntdll.dll", "SHELL32.dll", "ADVAPI32.dll", "USER32.dll", "KERNEL32.dll",
			"kernel32.dll", "hostfxr.dll", "comctl32.dll", "kernel32",

			"bad allocation", "bad array new length", "unordered_map/set too long", "invalid hash bucket count",
			"Unknown exception", "generic", "system", "string too long", "bad cast", "unknown error", "vector too long",
			"bad exception", "bad function call", "bad weak ptr", "bad variant access", "bad optional access",
			"bad any cast", "bad typeid", "bad alloc", "bad_alloc", "bad_cast", "bad_typeid", "bad_exception",
			"bad_function_call", "bad_weak_ptr", "bad_variant_access", "bad_optional_access", "bad_any_cast",
			"stoul argument out of range", "out of range", "length error", "domain error", "range error",
			"overflow error", "underflow error", "invalid argument", "logic error", "runtime error",
			"ios_base::failbit set", "ios_base::badbit set", "ios_base::eofbit set",
			"basic_string", "deque too long", "list too long", "forward_list too long",
			"regex_error", "invalid regex", "stack too long", "queue too long", "priority_queue too long",
			"invalid stoul argument",

			"Microsoft Visual C++ Runtime Library",
			"Runtime Error!", "Debug Error!", "Assertion failed!",
			"This application has requested the Runtime to terminate it in an unusual way.",
			"Please contact the application's support team for more information.",
			"R6002", "R6008", "R6009", "R6016", "R6017", "R6018", "R6019",
			"R6024", "R6025", "R6026", "R6028", "R6030", "R6031", "R6032", "R6033", "R6034",
			"pure virtual function call",
			"Buffer overrun detected!", "A buffer overrun has occurred", "Stack smashing detected",
			"HEAP CORRUPTION DETECTED", "heap corruption detected",
			"invalid heap pointer", "corrupted heap",
			"Abort() has been called", "abort() has been called",
			"terminate() has been called", "unexpected() has been called",
			"malloc failed", "realloc failed", "calloc failed",
			"out of memory", "Out of memory", "Out of Memory",
			"memory allocation failed", "Memory allocation failed",
			"cannot allocate memory", "Cannot allocate memory",
			"double free or corruption", "free(): invalid pointer",
			"free(): invalid size", "free(): corrupted unsorted chunks",
			"malloc(): memory corruption", "malloc(): corrupted top",
			"munmap_chunk(): invalid pointer",
			"corrupted double-linked list", "prev_size is incorrect",
			"Segmentation fault", "segmentation fault",
			"Bus error", "bus error",
			"Illegal instruction", "illegal instruction",
			"Floating point exception", "floating point exception",
			"division by zero", "Division by zero",
			"integer divide by zero", "Integer divide by zero",
			"errno", "perror", "strerror",
			"No such file or directory", "Permission denied", "File exists",
			"Too many open files", "No space left on device",
			"Broken pipe", "Connection refused", "Connection timed out",
			"No such process", "Invalid argument", "Function not implemented",
			"Operation not permitted", "Bad file descriptor",
			"Invalid address", "Address already in use",
			"EINVAL", "ENOMEM", "EACCES", "ENOENT", "EBADF", "EEXIST", "EAGAIN",
			"assert", "ASSERT", "assertion", "Assertion",
			"NULL pointer", "null pointer", "nullptr",
			"Access violation", "read access violation", "write access violation",

			"address family not supported", "address in use", "address not available", "bad locale name",
			"already connected", "argument list too long", "argument out of domain",
			"bad address", "bad message", "connection aborted", "connection already in progress",
			"connection reset", "cross device link", "destination address required",
			"device or resource busy", "directory not empty", "executable format error",
			"file too large", "filename too long", "function not supported", "host unreachable",
			"identifier removed", "illegal byte sequence", "inappropriate io control operation", "interrupted",
			"invalid seek", "io error", "is a directory", "message size", "network down", "network reset",
			"network unreachable", "no buffer space", "no child process", "no link", "no lock available",
			"no message available", "no message", "no protocol option", "no stream resources",
			"no such device or address", "no such device", "not a directory", "not a socket",
			"not a stream", "not connected", "not enough memory", "not supported",
			"operation canceled", "operation in progress", "operation not supported",
			"operation would block", "owner dead", "protocol error", "protocol not supported",
			"read only file system", "resource deadlock would occur", "resource unavailable try again",
			"result out of range", "state not recoverable", "stream timeout", "text file busy",
			"timed out", "too many files open in system", "too many files open", "too many links",
			"too many symbolic link levels", "value too large", "wrong protocol type",
			"bad file descriptor", "broken pipe", "connection refused", "file exists",
			"no space on device", "no such file or directory", "no such process",
			"operation not permitted", "permission denied", "invalid string position",
			"iostream", "iostream stream error",

			"Assembly Version", "ProductVersion", "ProductName", "OriginalFilename",
			"LegalCopyright", "InternalName", "FileVersion", "FileDescription", "CompanyName",
			"StringFileInfo", "Translation", "VarFileInfo", "WindowsShell.Manifest",
			"TRACEFILE", "VS_VERSION_INFO", "TRACE_VERBOSITY", "InstallLocation",
			"dotnet", "apphost", "success",
			"0123456789abcdefghijklmnopqrstuvwxyz", "0123456789",
			"GetSystemTimePreciseAsFileTime", "GetTempPath2W", "RtlGetVersion", "IsWow64Process2",
			"TaskDialogIndirect", "Detected Single-File app bundle", "The following locations were searched:", "Not found",

			"Application: ", "Message: ", "Required: ", "Architecture: ", "pal::load_library", "The following locations were searched:",
			"You will need to run the downloaded installer", "Error: the default install location cannot be obtained.",
			" - search options: [", " = <not set>", "Bundle header version compatibility check failed.", " was not found.",
			"Would you like to download it now?", "Redirecting errors to custom writer."

		}, 512
		);

	inline const std::vector<std::string_view> blocklist_substrings =
	{
		// CRT / runtime noise
		"not enough space for",
		"unable to open console device",
		"unexpected multithread lock error",
		"unexpected heap error",
		"not enough space for lowio initialization",
		"not enough space for stdio initialization",
		"invalid parameter passed to C runtime",
		"floating point support not loaded",
		"Stack overflow",
		"stack overflow",
		"DAMAGE: after",
		"DAMAGE: before",
		"Stack around the variable",
		"malloc: ",
		"free: ",
		"realloc: ",
		"calloc: ",
		"Exception at address",

		// .NET / hosting noise
		"missing_runtime=true",
		"loongarch64",
		"ppc64le",
		"riscv64",
		"win-x64",
		"app_local",
		"app_relative",
		"environment_variable",
		"app-relative path: ",
		"Ensure the library matches the current process architecture",
		"The managed DLL bound to this executable",
		"hostfxr_",
		"ProgramFiles",
		"&arch=",
		"aka.ms/",
		".NET",
		"DOTNET_",

		// Version-info / manifest noise
		" Base Class Descriptor at (",
		" delete[]",
		" delete",
		" new[]",
		"restrict(",
	};

	inline bool blocklist_word(std::string_view string)
	{
		if (blocklist_exact.contains(string))
		{
			return true;
		}

		for (std::string_view sub : blocklist_substrings)
		{
			if (string.find(sub) != std::string_view::npos)
			{
				return true;
			}
		}

		return false;
	}
}