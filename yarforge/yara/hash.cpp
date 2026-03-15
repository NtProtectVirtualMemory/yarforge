#include "serializer.hpp"

#include <stdexcept>
#include <openssl/evp.h>

namespace yarforge
{
	void yara_rule::set_hash() // Gracias Claude for this function
	{
		const std::vector<std::uint8_t>& data = m_image->Data();

		EVP_MD_CTX* ctx = EVP_MD_CTX_new();
		if (!ctx)
			throw std::runtime_error("Failed to create EVP_MD_CTX");

		if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("EVP_DigestInit_ex failed");
		}

		if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("EVP_DigestUpdate failed");
		}

		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int digest_len = 0;

		if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1)
		{
			EVP_MD_CTX_free(ctx);
			throw std::runtime_error("EVP_DigestFinal_ex failed");
		}

		EVP_MD_CTX_free(ctx);

		std::ostringstream oss;
		for (unsigned int i = 0; i < digest_len; ++i)
		{
			oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(digest[i]);
		}

		m_meta.push_back({ "hash", oss.str() });
	}
}