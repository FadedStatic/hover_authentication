#include "include.hpp"

namespace auth::getkey
{
	key to_key(const std::string_view in_str)
	{
		const auto split_key = database::split(in_str.data(), ':');
		return
		{
			static_cast<std::uint8_t>(std::stoi(split_key.at(0))),
			std::stol(split_key.at(1)),
			split_key.at(2)
		};
	}

	std::string to_fmt(const key& ky)
	{
		std::string ret_val{std::to_string(ky.ty)};
		ret_val.push_back(':');
		ret_val.append(std::to_string(ky.mins));
		ret_val.push_back(':');
		ret_val.append(ky.value);

		return ret_val;
	}
}