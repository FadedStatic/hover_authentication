#pragma once

#pragma unmanaged
#include <iostream>
#include <vector>
#include <string_view>
#include "argon2/argon2.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "hv/json.hpp"
#include "hv/http_client.h"
#include <intrin.h>
#include <chrono>
#include <comdef.h>
#include <Wbemidl.h>

namespace internals
{
	// This is reflected
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
	std::string get_hwid();

	static std::vector<std::uint8_t> encrypt_email(const std::string_view email),
		hash_password(const std::string_view password, const std::string_view salt), hash_hwid();

	authed_user reflect_user(const authed_user& usr), register_user(const std::string& usr, const std::string& email, const std::string& password), register_user(const authed_user& usr), get_regkey();
	static std::uint32_t init();

	static std::uint32_t set_regkey(const std::string& serialized);

	static authed_user json_to_user(const nlohmann::json& json);
	[[nodiscard]]
	std::string serialize_user(const authed_user& usr);
}

#pragma managed
#include <msclr/marshal_cppstd.h>
#define exported_func 
namespace clientclr {
	public ref class client
	{
	public:
		ref class authed_user
		{
		public:
			System::UInt32 subscription_type, is_online, user_id;
			System::Int64 unix_time_end;

			System::String^ user;
			System::Collections::Generic::List<System::Byte>^ email, ^ password, ^ hwid;
		}^ user;

		System::String^ serialized_user;

		exported_func System::String^ get_hwid()
		{
			auto ret = gcnew System::String(internals::get_hwid().data());
			return ret;
		}

		exported_func System::String^ serialize_user()
		{
			std::vector<std::uint8_t> email_cpp(user->email->Count);
			std::vector<std::uint8_t> password_cpp(user->password->Count);
			std::vector<std::uint8_t> hwid_cpp(user->hwid->Count);

			internals::authed_user user_cpp;

			user_cpp.subscription_type = static_cast<std::uint8_t>(user->subscription_type);
			user_cpp.is_online = static_cast<std::uint8_t>(user->is_online);
			user_cpp.user_id = user->user_id;
			user_cpp.unix_time_end = user->unix_time_end;

			System::String^ str_ref = user->user;
			user_cpp.user = std::string(msclr::interop::marshal_as<std::string>(str_ref));

			for each (System::Byte b in user->email) {
				user_cpp.email.push_back(static_cast<std::uint8_t>(b));
			}

			for each (System::Byte b in user->password) {
				user_cpp.password.push_back(static_cast<std::uint8_t>(b));
			}

			for each (System::Byte b in user->hwid) {
				user_cpp.hwid.push_back(static_cast<std::uint8_t>(b));
			}


			const auto ret = gcnew System::String(internals::serialize_user(user_cpp).data());
			return ret;
		}
		exported_func System::Collections::Generic::List<System::Byte>^ get_enckey(System::String^ orig_string)
		{
			const auto orig_string_cpp = msclr::interop::marshal_as<std::string>(orig_string);

			const auto enckey = internals::get_enckey(orig_string_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : enckey)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ get_enckey_inverse(System::String^ orig_string)
		{
			const auto orig_string_cpp = msclr::interop::marshal_as<std::string>(orig_string);

			const auto enckey = internals::get_enckey_inverse(orig_string_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : enckey)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ get_salt(System::String^ orig_string)
		{
			// Marshal string
			const auto orig_string_cpp = msclr::interop::marshal_as<std::string>(orig_string);

			const auto salt_vec = internals::get_salt(orig_string_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : salt_vec)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ get_salt_inverse(System::String^ orig_string)
		{
			// Marshal string
			const auto orig_string_cpp = msclr::interop::marshal_as<std::string>(orig_string);

			const auto salt_vec = internals::get_salt_inverse(orig_string_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : salt_vec)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ get_iv(System::String^ orig_string)
		{
			// Marshal string
			const auto orig_string_cpp = msclr::interop::marshal_as<std::string>(orig_string);

			const auto salt_vec = internals::get_iv(orig_string_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : salt_vec)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ get_iv_inverse(System::String^ orig_string)
		{
			// Marshal string
			const auto orig_string_cpp = msclr::interop::marshal_as<std::string>(orig_string);

			const auto salt_vec = internals::get_iv_inverse(orig_string_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : salt_vec)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ hash_information(System::String^ info, System::Collections::Generic::List<System::Byte>^ salt)
		{
			// Marshal string
			const auto info_cpp = msclr::interop::marshal_as<std::string>(info);

			std::vector<std::uint8_t> salt_cpp(salt->Count);
			msclr::interop::marshal_context context;
			for (int i = 0; i < salt->Count; i++) 
				salt_cpp[i] = static_cast<std::uint8_t>(salt[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			// C++ hashed vector
			const auto hash_vec = internals::hash_information(info_cpp, salt_cpp);


			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : hash_vec)
				ret->Add(byte);
			
			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ decrypt_information(System::Collections::Generic::List<System::Byte>^ info, System::Collections::Generic::List<System::Byte>^ iv, System::Collections::Generic::List<System::Byte>^ key)
		{
			std::vector<std::uint8_t> info_cpp(info->Count);
			std::vector<std::uint8_t> key_cpp(key->Count);
			std::vector<std::uint8_t> iv_cpp(iv->Count);
			msclr::interop::marshal_context context;
			for (int i = 0; i < info->Count; i++)
				info_cpp[i] = static_cast<std::uint8_t>(info[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			for (int i = 0; i < key->Count; i++)
				key_cpp[i] = static_cast<std::uint8_t>(key[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			for (int i = 0; i < iv->Count; i++)
				iv_cpp[i] = static_cast<std::uint8_t>(iv[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			const auto dec_vec = internals::decrypt_information(info_cpp, iv_cpp, key_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : dec_vec)
				ret->Add(byte);

			return ret;
		}

		exported_func System::Collections::Generic::List<System::Byte>^ encrypt_information(System::Collections::Generic::List<System::Byte>^ info, System::Collections::Generic::List<System::Byte>^ iv, System::Collections::Generic::List<System::Byte>^ key)
		{
			std::vector<std::uint8_t> info_cpp(info->Count);
			std::vector<std::uint8_t> key_cpp(key->Count);
			std::vector<std::uint8_t> iv_cpp(iv->Count);
			msclr::interop::marshal_context context;
			for (int i = 0; i < info->Count; i++)
				info_cpp[i] = static_cast<std::uint8_t>(info[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			for (int i = 0; i < key->Count; i++)
				key_cpp[i] = static_cast<std::uint8_t>(key[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			for (int i = 0; i < iv->Count; i++)
				iv_cpp[i] = static_cast<std::uint8_t>(iv[i]); // static_cast is for ease of use, so if we change from System::Byte to System::Char

			const auto enc_vec = internals::encrypt_information(info_cpp, iv_cpp, key_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : enc_vec)
				ret->Add(byte);

			return ret;
		}

		exported_func System::UInt32 encrypt_email(System::String^ email)
		{
			const auto email_cpp = msclr::interop::marshal_as<std::string>(email);

			const auto encrypted_email = internals::encrypt_email(email_cpp);

			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : encrypted_email)
				ret->Add(byte);

			this->user->email = ret;
			return 0;
		}

		exported_func System::UInt32 hash_password(System::String^ password, System::String^ salt)
		{
			// Marshal string
			const auto password_cpp = msclr::interop::marshal_as<std::string>(password);
			const auto salt_cpp = msclr::interop::marshal_as<std::string>(salt);

			const auto hashed_password = internals::hash_password(password_cpp, salt_cpp);
			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : hashed_password)
				ret->Add(byte);

			this->user->password = ret;
			return 0;
		}

		exported_func System::UInt32 hash_hwid()
		{
			const auto hashed_hwid = internals::hash_hwid();
			auto ret = gcnew System::Collections::Generic::List<System::Byte>();
			for (const auto& byte : hashed_hwid)
				ret->Add(byte);

			this->user->hwid = ret;
			return 0;
		}
		//exported_func System::UInt32 reflect_user();
		exported_func System::UInt32 register_user(System::String^ usr, System::String^ email, System::String^ password)
		{
			const auto usr_cpp = msclr::interop::marshal_as<std::string>(usr);
			const auto email_cpp = msclr::interop::marshal_as<std::string>(email);
			const auto password_cpp = msclr::interop::marshal_as<std::string>(password);
			const auto user_cpp = internals::register_user(usr_cpp, email_cpp, password_cpp);

			user->subscription_type = user_cpp.subscription_type;
			user->is_online = user_cpp.is_online;
			user->user_id = user_cpp.user_id;
			user->unix_time_end = user_cpp.unix_time_end;

			user->user = gcnew System::String(user_cpp.user.data());

			user->email = gcnew System::Collections::Generic::List<System::Byte>();
			user->password = gcnew System::Collections::Generic::List<System::Byte>();
			user->hwid = gcnew System::Collections::Generic::List<System::Byte>();

			for (const auto& b : user_cpp.email) {
				user->email->Add(b);
			}

			for (const auto& b : user_cpp.password) {
				user->password->Add(b);
			}

			for (const auto& b : user_cpp.hwid) {
				user->hwid->Add(b);
			}
			return 0;
		}
		//exported_func System::UInt32 register_user();
		//exported_func System::UInt32 get_regkey();
		//exported_func System::UInt32 init();
		//exported_func System::UInt32 set_regkey(System::String^ serialized);
		// Constructor that initializes the nested authed_user object
		client() {
			this->user = gcnew authed_user();
		}
	};
}
