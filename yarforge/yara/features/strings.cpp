#include "strings.hpp"
#include "yara/serializer.hpp"

namespace yarforge
{
	bool should_skip(std::string_view string, const std::vector<PE::ImportEntry>& imported_functions)
	{
		if (string.starts_with("_") || string.starts_with("?") || string.starts_with("."))
		{
			return true; // Section names, mangled MSVC names
		}

		if (string.starts_with("api-ms") || string.starts_with("MSVCP") || string.starts_with("VCRUNTIME") || string.starts_with("KERNEL32"))
		{
			return true; // Runtime names
		}

		for (const auto& entry : imported_functions)
		{
			for (const auto& fn : entry.functions)
			{
				if (string == fn.name)
				{
					return true;
				}
			}
		}

		if (blocklist_word(string))
		{
			return true;
		}

		return false;
	}

	void yara_rule::get_strings()
	{
		PE::Imports imports(m_image.get()); // Needed to filter from strings
		PE::Utils image_utils(m_image.get());
		const auto imported_modules = imports.GetAllImports();

		for (const auto& string : image_utils.GetAsciiStrings(6))
		{
			if (should_skip(string, imported_modules))
			{
				continue;
			}

			printf("[] %.*s\n", (int)string.size(), string.data());

			if (string.ends_with(".pdb"))
			{
				char input[1];
				printf("[?] Include The PDB file path? (y/n): ");
				
				if (scanf_s("%3s", input, (unsigned)sizeof(input)))
				{
					if (input[0] == 'n' || input[0] == 'N')
					{
						continue;
					}
				}

			}
			m_strings.push_back({ string.data(), "fullword ascii" });
		}
	}
}
