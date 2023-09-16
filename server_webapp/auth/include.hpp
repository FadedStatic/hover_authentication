#pragma once

#include "../database/init.hpp"
#include <regex>
/*
 * This header serves as a wrapper between Drogon and the database.
 *
 */
namespace auth
{

	namespace getkey
	{
		struct usr_session
		{
			// stage_ct is the count along the way
			// commit_ct is the committed amount of times to have it done
			// previous_timestamp is the time that they last did the thing
			std::uint8_t stage_ct{ 0 }, commit_ct{ 0 };
			std::uint64_t previous_timestamp;
			const authed_user& usr;
			std::string hash;

			usr_session(const std::uint8_t stage_ct_a, const std::uint8_t commit_ct_a, const std::uint64_t previous_timestamp_a, const authed_user& usr_a, const std::string& hash_a) : stage_ct(stage_ct_a), commit_ct(commit_ct_a), previous_timestamp(previous_timestamp_a), usr(usr_a),hash(std::move(hash_a)) {  }
		};

		inline std::string random_string(const size_t length)
		{
			std::string str(length, 0);
			std::generate_n(str.begin(), length, [&]
				{
					constexpr char charset[] =
						"0123456789"
						"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
						"abcdefghijklmnopqrstuvwxyz";
					constexpr size_t max_index = sizeof charset - 1;
					return charset[rand() % max_index];
				});
			return str;
		}

		struct key
		{
			// type, 0=free,1=prem
			std::uint8_t ty{0};

			// dur = duration (minutes)
			std::int64_t mins{0};

			std::string value;

			key(std::uint8_t _ty, std::int64_t _mins, const std::string& _value = "") : ty(_ty), mins(_mins), value(std::move(_value))
			{

				if (_value.empty()) 
				{
					auto randkey = random_string(40);
					randkey.insert(8, "-");
					randkey.insert(17, "-");
					randkey.insert(26, "-");
					randkey.insert(35, "-");
				}
			}
		};

		key to_key(const std::string_view in_str);
		std::string to_fmt(const key& ky);

		class getkey_t
		{
		public:
			std::vector<usr_session> sessions;
			std::vector<key> keys;

			explicit getkey_t() = default;

			explicit getkey_t(const std::string& path)
			{
				if (!std::filesystem::exists(path.data()))
					std::fstream(path.data(), std::ios::out).close();

				// load DB from db_path, split by lines and then append to array (or do it magically)
				auto main_fs = std::fstream(path.data(), std::ios::in | std::ios::out | std::ios::binary);

				if (main_fs.peek() == std::ifstream::traits_type::eof())
					return;

				std::string tmp_str;
				while (std::getline(main_fs, tmp_str))
				{
					this->keys.push_back(to_key(tmp_str));
				}
			}
		};

		inline auto get()
		{
			return std::make_unique<getkey_t>();
		}

		inline auto get(const std::string& path)
		{
			return std::make_unique<getkey_t>(path);
		}
	}
}