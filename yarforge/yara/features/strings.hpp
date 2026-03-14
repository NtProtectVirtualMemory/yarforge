#pragma once

#include <string_view>
#include <unordered_set>

namespace yarforge
{
	inline const std::unordered_set<std::string_view> blocklist =
	{
		 "bad allocation", "bad array new length", "unordered_map/set too long", "invalid hash bucket count",
		"Unknown exception", "generic", "system", "string too long", "bad cast", "unknown error", "vector too long",
		"bad exception", "bad function call", "bad weak ptr", "bad variant access", "bad optional access",
		"bad any cast", "bad typeid", "bad alloc", "bad_alloc", "bad_cast", "bad_typeid", "bad_exception",
		"bad_function_call", "bad_weak_ptr", "bad_variant_access", "bad_optional_access",
		"out of range", "length error", "domain error", "range error", "overflow error", "underflow error",
		"invalid argument", "logic error", "runtime error", "ios_base::failbit set", "ios_base::badbit set",
		"ios_base::eofbit set", "basic_string", "deque too long", "list too long", "forward_list too long",
		"regex_error", "invalid regex", "stack too long", "queue too long", "priority_queue too long",

		"Microsoft Visual C++ Runtime Library",
		"Runtime Error!", "Debug Error!", "Assertion failed!",
		"This application has requested the Runtime to terminate it in an unusual way.",
		"Please contact the application's support team for more information.",
		"R6002", "R6008", "R6009", "R6016", "R6017", "R6018", "R6019",
		"R6024", "R6025", "R6026", "R6028", "R6030", "R6031", "R6032", "R6033", "R6034",
		"not enough space for arguments", "not enough space for environment",
		"not enough space for thread data", "not enough space for locale information",
		"not enough space for", "unable to open console device",
		"unexpected multithread lock error", "unexpected heap error",
		"pure virtual function call", "not enough space for lowio initialization",
		"not enough space for stdio initialization", "invalid parameter passed to C runtime",
		"floating point not loaded", "floating point support not loaded",
		"Stack overflow", "Stack Overflow", "stack overflow",
		"Buffer overrun detected!", "Stack around the variable",
		"A buffer overrun has occurred", "Stack smashing detected",
		"HEAP CORRUPTION DETECTED", "heap corruption detected",
		"invalid heap pointer", "corrupted heap",
		"DAMAGE: after", "DAMAGE: before",

		"Abort() has been called", "abort() has been called",
		"terminate() has been called", "unexpected() has been called",
		"malloc: ", "free: ", "realloc: ", "calloc: ",
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
		"Exception at address", "Access violation",
		"read access violation", "write access violation"
	};

	inline bool blocklist_word(std::string_view string)
	{
		return blocklist.count(string);
	}
}

