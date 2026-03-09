#include <cstdio>
#include <thread>

#include "pe-lib/pe.h"
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
		printf("[!] Bad boy.");
		wait(std::chrono::seconds(2));

		return 1;
	}

	PE::Image sample(argv[1]);

	return 0;

}