#include "strings.hpp"
#include "yara/serializer.hpp"
#include <unordered_map>

namespace yarforge
{
	struct StringEntry {
		std::string value;
		std::string modifier;
	};

	static std::string wide_to_utf8(const std::wstring_view wide)
	{
		if (wide.empty())
		{
			return {};
		}

		int size = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
		std::string result(size, '\0');
		WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), result.data(), size, nullptr, nullptr);

		return result;
	}

	static std::string reinterpret_utf16_to_utf8(const std::string_view raw)
	{
		const wchar_t* wide_ptr = reinterpret_cast<const wchar_t*>(raw.data());
		const size_t wide_len = raw.size() / sizeof(wchar_t);
		return wide_to_utf8({ wide_ptr, wide_len });
	}

	static bool should_skip(const std::string_view string, const std::vector<PE::ImportEntry>& imported_functions)
	{
		if (std::all_of(string.begin(), string.end(), [](unsigned char c) { return std::isspace(c); }))
		{
			return true;
		}

		if (std::all_of(string.begin(), string.end(), [](unsigned char c) {
			return std::isupper(c) || std::isdigit(c) || c == '_';
			}))
		{
			return true;
		}

		if (string.starts_with("_") || string.starts_with("?") ||
			string.starts_with(".") || string.starts_with("<") ||
			string.starts_with("!") || string.starts_with("&"))
		{
			return true;
		}

		if (string.starts_with("api-ms") || string.starts_with("MSVCP") || string.starts_with("VCRUNTIME"))
		{
			return true;
		}

		if (string.starts_with("`") || string.starts_with("Fls") || string.starts_with("operator"))
		{
			return true;
		}

		if (string.ends_with("'") && !string.starts_with("'"))
		{
			return true;
		}

		if (string.find('\\') != std::string_view::npos)
		{
			return true;
		}

		if (string.find('%') != std::string_view::npos)
		{
			return true;
		}

		for (const auto& entry : imported_functions)
		{
			for (const auto& fn : entry.functions)
			{
				if (string == fn.name)
					return true;
			}
		}

		if (blocklist_word(string))
		{
			return true;
		}

		return false;
	}

	static bool prompt_pdb(const std::string_view string)
	{
		printf("[+] PDB file found: %.*s\n", (int)string.size(), string.data());
		printf("[?] Include PDB path in rule? (y/n): ");

		char input[4] = {};
		if (scanf_s("%3s", input, (unsigned)sizeof(input)))
		{
			if (input[0] == 'n' || input[0] == 'N')
			{
				return false;
			}
		}

		return true;
	}

	void yara_rule::get_strings()
	{
		PE::Imports imports(m_image.get());
		PE::Utils image_utils(m_image.get());
		const auto imported_modules = imports.GetAllImports();

		// Thank you leetcode
		std::unordered_map<std::string, std::string> seen;
		auto collect = [&](std::string_view string, bool is_unicode)
			{
				if (string.ends_with(".pdb"))
				{
					if (!prompt_pdb(string))
					{
						return;
					}
				}
				else if (should_skip(string, imported_modules))
				{
					return;
				}

				printf("[ ] %.*s\n", (int)string.size(), string.data());
				const std::string_view modifier = is_unicode ? "fullword wide" : "fullword ascii";

				auto [it, inserted] = seen.emplace(std::string(string), modifier);
				if (!inserted && it->second != modifier)
				{
					it->second = "fullword ascii wide";
				}
			};

		for (const auto& string : image_utils.GetAsciiStrings(8))
		{
			collect(string, false);
		}

		for (const auto& string : image_utils.GetUnicodeStrings(8))
		{
			collect(reinterpret_utf16_to_utf8(string), true);
		}

		for (auto& [value, modifier] : seen)
		{
			m_strings.push_back({ value, modifier });
		}
	}
}