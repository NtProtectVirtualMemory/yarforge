#include "serializer.hpp"

#include <fstream>
#include <filesystem>

namespace yarforge
{
	static std::string escape_for_yara(const std::string& s)
	{
		std::string result;
		result.reserve(s.size());
		for (char c : s)
		{
			if (c == '"')
				result += "\\\"";
			else if (c == '\\')
				result += "\\\\";
			else
				result += c;
		}
		return result;
	}

	void yara_rule::serialize()
	{
		int counter{ 0 }; // very important counter!
		std::filesystem::create_directories("signatures");
		std::string file_path = "signatures\\" + m_name + ".yar";
		std::ofstream rule(file_path);

		rule << "rule " << m_name << " {";
		rule << "\n\tmeta:";
		for (const auto& [k, v] : m_meta)
		{
			rule << "\n\t\t" << k << " = \"" << v << "\"";
		}

		if (!m_strings.empty())
		{
			rule << "\n\tstrings:";
			for (const auto& [c, m] : m_strings)
			{
				rule << "\n\t\t$s" << counter++ << " = \"" << escape_for_yara(c) << "\" " << m;
			}
			counter = 0;
		}

		// Every YARA Rule must have a condition
		rule << "\n\tcondition:";
		if (m_conditions.empty()) {
			rule << "\n\t\ttrue";
		}
		else {
			for (size_t i = 0; i < m_conditions.size(); ++i) {
				rule << "\n\t\t" << m_conditions[i];
				if (i < m_conditions.size() - 1) {
					rule << " and";
				}
			}
		}

		rule << "\n}";
	}
}