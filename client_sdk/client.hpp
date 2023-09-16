#pragma once

#include <iostream>
#include <vector>
#include <string_view>

namespace client
{
	struct client_t
	{
	public:

		// This is reflected
		struct authed_user
		{
			// Unencrypted
			std::uint8_t subscription_type{0} /* 0 for free, 1 for paid.*/, is_online{0};
			// 0 for false, anything else for true.

			std::uint32_t user_id{0}; // we won't ever have 4 billion users

			std::int64_t unix_time_end{0}; // -1 for infinite, 0 for no time added.

			std::string user;
			// Encrypted: email; hashed: password, hwid
			std::vector<std::uint8_t> email, password, hwid;
		} user;

		// JSon serialized user
		std::string serialized_user;

		// Grab parts of enc key with custom substring
		static std::vector<std::uint8_t> get_enckey(const std::string_view orig_string);

		// Grab parts of enc key with custom substring
		static std::vector<std::uint8_t> get_enckey_inverse(const std::string_view orig_string);

		// Grab parts of enc key with custom substring
		static std::vector<std::uint8_t> get_salt(const std::string_view orig_string);

		// Grab parts of enc key with custom substring
		static std::vector<std::uint8_t> get_salt_inverse(const std::string_view orig_string);

		// Grab parts of enc key with custom substring
		static std::vector<std::uint8_t> get_iv(const std::string_view orig_string);

		// Grab parts of enc key with custom substring
		static std::vector<std::uint8_t> get_iv_inverse(const std::string_view orig_string);

		// Hash the information
		static std::vector<std::uint8_t> hash_information(const std::string_view info,
		                                                  const std::vector<std::uint8_t>& salt);

		// Encrypt information
		static std::vector<std::uint8_t> decrypt_information(const std::vector<std::uint8_t>& info, 
					const std::vector<std::uint8_t>& iv, 
					const std::vector<std::uint8_t>& key),
										 encrypt_information(
					const std::vector<std::uint8_t>& info,
					const std::vector<std::uint8_t>& iv,
					const std::vector<std::uint8_t>& key);
		[[nodiscard]]
		std::string get_hwid() const;

		std::uint32_t encrypt_email(const std::string_view email),
			hash_password(const std::string_view password, const std::string_view salt), hash_hwid(), reflect_user(), register_user(const std::string& usr, const std::string& email, const std::string& password), register_user(), get_regkey(), init();

		static std::uint32_t set_regkey(const std::string& serialized);


		[[nodiscard]]
		std::string serialize_user() const;

		explicit client_t() : user({})
		{
		}
	};

	inline auto get()
	{
		return std::make_unique<client_t>();
	}
}