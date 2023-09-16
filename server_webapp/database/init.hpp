#pragma once

#include <vector>
#include <span>
#include <string_view>
#include <filesystem>
#include <fstream>
#include <json/value.h>
#include <algorithm>
struct authed_user
{
	// Unencrypted
	std::uint8_t subscription_type{ 0 } /* 0 for free, 1 for paid.*/, is_online{ 0 };
	// 0 for false, anything else for true.

	std::uint32_t user_id{ 0 }; // we won't ever have 4 billion users

	std::int64_t unix_time_end{ 0 }; // -1 for infinite, 0 for no time added.

	std::string user;
	// Encrypted: email; hashed: password, hwid
	std::vector<std::uint8_t> email, password, hwid;
};

namespace database
{
	std::vector < std::uint8_t> to_hex(const std::string_view bytes);

	authed_user json_to_user(const Json::Value& json);
	authed_user json_to_site_user(const Json::Value& json);

	std::vector<std::string> split(const std::string& s, char delimiter);

	Json::Value to_value(const std::string_view str);

	template <typename I>
	auto to_hexstr(const I w, const std::size_t hex_len = sizeof(I) << 1)
	{
		static auto digits = "0123456789ABCDEF";

		std::string rc(hex_len, '0');

		for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
			rc[i] = digits[w >> j & 0x0f];

		return rc;
	}

	std::string serialize_user(const authed_user& user);

	// ignore
	std::vector<std::string> split(const std::string& s, const char delimiter);

	class database_t
	{
		std::string fs_path_;
		std::uint32_t total_registered_{ 0 }/*another global metric*/, authed_count_{ 0 }; // Sort of a global metric with no real value
		std::vector<authed_user> users_;
		
		// If something is cleared then prioritize it. Check if this is empty, if not then add to empty space.
		std::vector<std::uint32_t> blank_entries_;

		std::string to_fmt(const authed_user& usr) const;
		Json::Value to_value(const std::string_view str) const;
	public:
		/*
		 * Functions needed:
		 * add_entry(const authed_user& user) - add a user
		 * del_entry(const authed_user& user) - delete an entry (NOT WORKING IF THEY ARE PAID)
		 * get_user(const authed_user& user) - send user from DB (priority is array, then file), before sending back information we must verify what is at ID is actually the same as user and password.
		 * reflect_user(const authed_user& user) - this is to sync all data we have about user, usually called after.
		 * load_db(const std::string_view db_path) - this is to load a db
		 */
		[[nodiscard]]
		std::uint32_t get_authed_count(), get_total_registered() const, add_entry(const authed_user& user, authed_user& replicated), del_entry(const authed_user& user), register_user(const authed_user& user) const, load_db(const std::string_view db_path), overwrite_user(const authed_user& user) const;

		authed_user get_user(const authed_user& user) const;
		authed_user get_user_by_email(const authed_user& user) const;

		database_t() = default;
		database_t(const std::string_view db_path) : fs_path_{ db_path } { load_db(db_path); }
	};

	inline auto get()
	{
		return std::make_unique<database_t>();
	}
	inline auto get(const std::string_view db_path)
	{
		return std::make_unique<database_t>(db_path);
	}
}