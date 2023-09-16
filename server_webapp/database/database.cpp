#include <iostream>

#include "init.hpp"

namespace database
{
	std::vector < std::uint8_t> to_hex(const std::string_view bytes)
	{
		std::vector < std::uint8_t> ret;
		if (bytes.size() % 2 != 0)
			throw std::invalid_argument("Bad JSon object.");

		for (auto it = bytes.begin(); it != bytes.end(); it += 2)
		{
			std::string hexbuf{ it, it + 2 };
			ret.push_back(static_cast<std::uint8_t>(std::stoul(hexbuf, nullptr, 16)));
		}

		return ret;
	}

	authed_user json_to_user(const Json::Value& json)
	{
		return {
			static_cast<std::uint8_t>(json["subscription_type"].asUInt()),
			static_cast<std::uint8_t>(json["is_online"].asUInt()),

			json["user_id"].asUInt(),
			json["unix_time_end"].asUInt(),
			json["user"].asString(),

			to_hex(json["email"].asString()),
			to_hex(json["password"].asString()),
			to_hex(json["hwid"].asString())
		};
	}

	authed_user json_to_site_user(const Json::Value& json)
	{
		return {
			static_cast<std::uint8_t>(0),
			static_cast<std::uint8_t>(0),

			0,
			0,
			"",

			to_hex(json["email"].asString()),
			to_hex(json["password"].asString()),
			{0}
		};
	}

	std::vector<std::string> split(const std::string& s, char delimiter)
	{
		std::vector<std::string> tokens;
		std::string token;
		std::istringstream token_stream(s);

		while (getline(token_stream, token, delimiter))
		{
			tokens.push_back(token);
		}

		return tokens;
	}

	Json::Value to_value(const std::string_view str)
	{
		Json::Value ret;
		const auto ir = split(str.data(), ':');
		ret["user_id"] = std::stoi(ir.at(0));
		ret["user"] = ir.at(1);
		ret["email"] = ir.at(2);
		ret["password"] = ir.at(3);
		ret["hwid"] = ir.at(4);
		ret["subscription_type"] = std::stoi(ir.at(5));
		ret["unix_time_end"] = std::stoi(ir.at(6));
		ret["is_online"] = std::stoi(ir.at(7));
		return ret;
	}

	std::string serialize_user(const authed_user& user)
	{
		if (user.email.size() < 8 or user.email.size() > 64 or user.hwid.size() != 32 or user.
			password.size() != 32 or user.user.size() < 4 or user.user.size() > 16)
			return "";

		std::string email, password, hwid;

		for (const auto& c : user.email)
			email.append(database::to_hexstr(static_cast<std::int8_t>(c)));
		for (const auto& c : user.password)
			password.append(database::to_hexstr(static_cast<std::int8_t>(c)));
		for (const auto& c : user.hwid)
			hwid.append(database::to_hexstr(static_cast<std::int8_t>(c)));

		Json::Value json_value;
		json_value["subscription_type"] = user.subscription_type;
		json_value["is_online"] = user.is_online;
		json_value["user_id"] = user.user_id;
		json_value["unix_time_end"] = user.unix_time_end;
		json_value["user"] = user.user;
		json_value["email"] = email;
		json_value["password"] = password;
		json_value["hwid"] = hwid;
		return json_value.toStyledString();
	}

	std::string database_t::to_fmt(const authed_user& usr) const
	{
		std::string ret;
		ret.append(std::to_string(usr.user_id) + ":");
		ret.append(usr.user + ":");
		std::string email, password, hwid;

		for (const auto& c : usr.email)
			email.append(to_hexstr(static_cast<std::int8_t>(c)));
		for (const auto& c : usr.password)
			password.append(to_hexstr(static_cast<std::int8_t>(c)));
		for (const auto& c : usr.hwid)
			hwid.append(to_hexstr(static_cast<std::int8_t>(c)));

		ret.append(email + ":");
		ret.append(password + ":");
		ret.append(hwid + ":");
		ret.append(std::to_string(usr.subscription_type) + ":");
		ret.append(std::to_string(usr.unix_time_end) + ":");
		ret.append(std::to_string(usr.is_online));
		return ret;
	}

	Json::Value database_t::to_value(const std::string_view str) const
	{
		Json::Value ret;
		const auto ir = split(str.data(), ':');
		ret["user_id"] = std::stoi(ir.at(0));
		ret["user"] = ir.at(1);
		ret["email"] = ir.at(2);
		ret["password"] = ir.at(3);
		ret["hwid"] = ir.at(4);
		ret["subscription_type"] = std::stoi(ir.at(5));
		ret["unix_time_end"] = std::stoi(ir.at(6));
		ret["is_online"] = std::stoi(ir.at(7));
		return ret;
	}


	std::uint32_t database_t::add_entry(const authed_user& user, authed_user& replicated)
	{
		authed_user cpy;
		cpy.user_id = ++total_registered_;
		cpy.email = user.email;
		cpy.hwid = user.hwid;
		cpy.password = user.password;
		cpy.user = user.user;
		cpy.is_online = 0;
		cpy.unix_time_end = 0;
		cpy.subscription_type = 0;

		replicated = cpy;
		std::string line, hwid;

		for (const auto& c : cpy.hwid)
			hwid.append(to_hexstr(static_cast<std::int8_t>(c)));

		auto main_fs = std::fstream(fs_path_, std::ios::in);
		while (std::getline(main_fs, line))
		{
			if (line.find(cpy.user) != std::string::npos)
				return 1;
			if (line.find(hwid) != std::string::npos)
				return 2;
		}

		// check user, if the username and password is secure (not violating HSIMP)
		// verify the HWID isn't already registered, and verify that the Email isn't already registered.
		if (!this->blank_entries_.empty())
		{
			this->users_[blank_entries_.back()] = cpy;
			this->blank_entries_.pop_back();
			return register_user(cpy);
		}

		this->users_.emplace_back(cpy);
		return register_user(cpy);
	}

	std::uint32_t database_t::del_entry(const authed_user& user)
	{
		// check if user exists, then check if premium.
		return 0;
	}

	std::uint32_t database_t::get_authed_count()
	{
		this->authed_count_ = this->users_.size();
		return this->authed_count_;
	}

	std::uint32_t database_t::get_total_registered() const
	{
		return this->total_registered_;
	}

	authed_user database_t::get_user(const authed_user& user) const
	{

		if (const auto iter = std::ranges::find_if(this->users_.begin(), this->users_.end(), [&](const authed_user& c) {
			return (c.user == user.user and c.email == user.email and c.hwid == user.hwid and c.password == user.password);
			}); iter != this->users_.end())
		{
			return *iter;
		}

		return{0,0,0,0,"INVALID", {}, {}, {}};
	}

	authed_user database_t::get_user_by_email(const authed_user& user) const
	{
		if (const auto iter = std::ranges::find_if(this->users_.begin(), this->users_.end(), [&](const authed_user& c) {
			return (c.email == user.email and c.password == user.password);
			}); iter != this->users_.end())
		{
			return *iter;
		}

		return{ 0,0,0,0,"INVALID", {}, {}, {} };
	}

	std::uint32_t database_t::load_db(const std::string_view db_path)
	{
		if (!std::filesystem::exists(db_path.data()))
			std::fstream(db_path.data(), std::ios::out).close();

		// load DB from db_path, split by lines and then append to array (or do it magically)
		auto main_fs = std::fstream(db_path.data(), std::ios::in | std::ios::out | std::ios::binary);

		if (main_fs.peek() == std::ifstream::traits_type::eof())
			return 0;

		std::string tmp_str;
		while (std::getline(main_fs, tmp_str))
		{
			this->users_.push_back(json_to_user(this->to_value(tmp_str)));
		}

		this->total_registered_ = static_cast<std::uint32_t>(this->users_.size());
		return 1;
	}

	std::uint32_t database_t::register_user(const authed_user& user)  const
	{
		std::vector<std::string> lines;
		std::string line;
		std::uint32_t line_ct{1}, pos{0};
		
		//std::ofstream ofs(this->fs_path_);
		// TODO: split lines
		auto main_fs = std::fstream(fs_path_, std::ios::in);

		while (std::getline(main_fs, line))
		{
			if (user.user_id == line_ct)
				break;

			pos += line.length();
			lines.push_back(line);
			line_ct++;
		}

		main_fs.close();
		auto write_fs = std::fstream(fs_path_, std::ios::app | std::ios::out | std::ios::binary);
		write_fs.seekp(pos);
		write_fs << to_fmt(user) << "\n";
		write_fs.close();
		return 0;
	}

	std::uint32_t database_t::overwrite_user(const authed_user& user) const
	{
		//std::ofstream ofs(this->fs_path_);
		// TODO: split lines
		std::vector<std::string> lines;
		std::string line;
		std::uint32_t line_ct{ 1 }, pos{ 0 };
		auto main_fs = std::fstream(fs_path_, std::ios::in);

		while (std::getline(main_fs, line))
		{
			if (user.user_id == line_ct)
			{
				// DROP table entry and serialize instead
				const auto& usr = serialize_user(user);
				lines.push_back(usr);
				pos += usr.length();
				line_ct++;
				continue;
			}

			pos += line.length();
			lines.push_back(line);
			line_ct++;
		}

		auto write_fs = std::fstream(fs_path_, std::ios::app | std::ios::out | std::ios::binary);

		for (const auto& c : lines)
			write_fs << c << "\r\n";
		write_fs.close();

		return 0;
	}
}