#pragma once

#include <ctime>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>

#include "pe-lib/pe.h"

namespace yarforge
{
	class yara_rule
	{
	public:
		yara_rule(std::string file_path) : m_image(std::make_unique<PE::Image>(file_path.c_str()))
		{
			std::tm tm_info{};
			std::time_t t = std::time(nullptr);

			char date_buf[11] = "1970-01-01";
			if (localtime_s(&tm_info, &t) == 0)
			{
				std::strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", &tm_info);
			}

			// Meta values
			m_meta.push_back({ "description", "yarforge generated this!" });
			m_meta.push_back({ "author", "crim" });
			m_meta.push_back({ "reference", "https://github.com/NtProtectVirtualMemory/yarforge" });
			m_meta.push_back({ "date", date_buf });

			try
			{
				set_hash();
			}
			catch (const std::exception& e)
			{
				printf("Exception: %s\n", e.what());
			}

			// Getting the rule name
			m_name = std::filesystem::path(file_path).stem().string();
			for (char& c : m_name) {
				if (std::isalnum(static_cast<unsigned char>(c))) {
					c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
				}
				else {
					c = '_';
				}
			}

			// YARA rules cant start with a digit
			if (std::isdigit(static_cast<unsigned char>(m_name[0]))) 
			{
				m_name.insert(0, 1, '_');
			}

			auto new_end = std::unique(m_name.begin(), m_name.end(), [](char a, char b) 
			{
				return a == '_' && b == '_'; // Gracias Claude for this
			});

			m_name.erase(new_end, m_name.end());

			// Remove underscores at the end of the name
			if (!m_name.empty() && m_name.back() == '_') 
			{
				m_name.pop_back();
			}

			// Do magic
			get_strings();

			// Put together everything
			serialize();
		};
		~yara_rule() = default;

	private:
		std::string m_name;
		std::unique_ptr<PE::Image> m_image;

		std::vector<std::pair<std::string, std::string>> m_meta;
		std::vector<std::pair<std::string, std::string>> m_strings;
		std::vector<std::string> m_conditions;

		void serialize();
		void set_hash();
		void get_strings();
	};
};