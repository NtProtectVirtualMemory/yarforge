#include <cstdio>
#include <thread>

#include "yara/serializer.hpp"

template <typename Rep, typename Period>
__forceinline static void wait(std::chrono::duration<Rep, Period> duration) noexcept
{
	std::this_thread::sleep_for(duration);
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		printf("[!] No input file.");
		wait(std::chrono::seconds(2));

		return 1;
	}

	yarforge::yara_rule signature(argv[1]);
	wait(std::chrono::seconds(2));

	return 0;
}