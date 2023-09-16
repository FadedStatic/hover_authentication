#include "client.hpp"

//#include "aes256/aes256.hpp"
#include "argon2/argon2.h"
#include "openssl/evp.h"
#include "openssl/aes.h"
#include "hv/json.hpp"
#include "hv/http_client.h"
#include <intrin.h>
#include <chrono>

#include "types.h"

#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

std::vector<std::uint8_t> client::client_t::get_enckey(const std::string_view orig_string)
{
	std::vector<std::uint8_t> ret;
	ret.reserve(orig_string.length());

	std::uint32_t left{ 0 }, right{ orig_string.length() - 1 };
	bool left_turn{ true };

	while (ret.size() < 32)
	{
		if (left > right)
		{
			left = 0; right = orig_string.length() - 1;
		}

		ret.emplace_back(left_turn ? orig_string.at(left++) : orig_string.at(right--));
		left_turn = !left_turn;
	}

	return ret;
}

std::vector<std::uint8_t> client::client_t::get_enckey_inverse(const std::string_view orig_string)
{
	std::vector<std::uint8_t> ret;
	ret.reserve(orig_string.length());

	std::uint32_t left{ 0 }, right{ orig_string.length() - 1 };
	bool right_turn{ true };

	while (ret.size() < 32)
	{
		if (left > right)
		{
			left = 0; right = orig_string.length() - 1;
		}

		ret.emplace_back(right_turn ? orig_string.at(right--) : orig_string.at(left++));
		right_turn = !right_turn;
	}

	return ret;
}

std::vector<std::uint8_t> client::client_t::get_salt(const std::string_view orig_string)
{
	std::vector<std::uint8_t> ret;
	ret.reserve(orig_string.length());

	std::uint32_t left{ 0 }, right{ orig_string.length() - 1 };
	bool left_turn{ true };

	while (left <= right)
	{
		if (left > right)
		{
			left = 0; right = orig_string.length() - 1;
		}

		ret.emplace_back(left_turn ? orig_string.at(left++) : orig_string.at(right--));
		left_turn = !left_turn;
	}

	return ret;
}

std::vector<std::uint8_t> client::client_t::get_salt_inverse(const std::string_view orig_string)
{
	std::vector<std::uint8_t> ret;
	ret.reserve(orig_string.length());

	std::uint32_t left{ 0 }, right{ orig_string.length() - 1 };
	bool right_turn{ true };

	while (left <= right)
	{
		if (left > right)
		{
			left = 0; right = orig_string.length() - 1;
		}

		ret.emplace_back(right_turn ? orig_string[right--] : orig_string[left++]);
		right_turn = !right_turn;
	}

	return ret;
}

std::vector<std::uint8_t> client::client_t::get_iv(const std::string_view orig_string)
{
	std::vector<std::uint8_t> ret;
	ret.reserve(orig_string.length());

	std::uint32_t left{ 0 }, right{ orig_string.length() - 1 };
	bool left_turn{ true };

	while (ret.size() < 16)
	{
		if (left > right)
		{
			left = 0; right = orig_string.length() - 1;
		}

		ret.emplace_back(left_turn ? orig_string.at(left++) : orig_string.at(right--));
		left_turn = !left_turn;
	}

	return ret;
}

std::vector<std::uint8_t> client::client_t::get_iv_inverse(const std::string_view orig_string)
{
	std::vector<std::uint8_t> ret;
	ret.reserve(orig_string.length());

	std::uint32_t left{ 0 }, right{ orig_string.length() - 1 };
	bool right_turn{ true };

	while (ret.size() < 16)
	{
		if (left > right)
		{
			left = 0; right = orig_string.length() - 1;
		}

		ret.emplace_back(right_turn ? orig_string.at(right--) : orig_string.at(left++));
		right_turn = !right_turn;
	}

	return ret;
}

std::vector<std::uint8_t> client::client_t::encrypt_information(const std::vector<std::uint8_t>& info,
	const std::vector<std::uint8_t>& iv,
	const std::vector<std::uint8_t>& key)
{
	std::vector<std::uint8_t> tmp(info.size() + EVP_MAX_BLOCK_LENGTH); // allocate enough space for output
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
		throw std::runtime_error("Error in creating the encryption context");

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
		throw std::runtime_error("Error in initializing the encryption operation");

	int len;
	if (EVP_EncryptUpdate(ctx, tmp.data(), &len, info.data(), info.size()) != 1)
		throw std::runtime_error("Error in encrypting the plaintext");

	int final_len;
	if (EVP_EncryptFinal_ex(ctx, tmp.data() + len, &final_len) != 1)
		throw std::runtime_error("Error in finalizing the encryption");

	EVP_CIPHER_CTX_free(ctx);
	tmp.resize(len + final_len);

	return tmp;
}

std::vector<std::uint8_t> client::client_t::decrypt_information(const std::vector<std::uint8_t>& info,
	const std::vector<std::uint8_t>& iv,
	const std::vector<std::uint8_t>& key)
{
	std::vector<std::uint8_t> tmp(info.size() + EVP_MAX_BLOCK_LENGTH); // allocate enough space for output
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr)
		throw std::runtime_error("Error in creating the decryption context");

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1)
		throw std::runtime_error("Error in initializing the decryption operation");

	int len;
	if (EVP_DecryptUpdate(ctx, tmp.data(), &len, info.data(), info.size()) != 1)
		throw std::runtime_error("Error in decrypting the ciphertext");

	int ret;
	if ((ret = EVP_DecryptFinal_ex(ctx, tmp.data() + len, &len)) <= 0)
		throw std::runtime_error("Error in finalizing the decryption");

	len += ret - 1; // add the number of bytes written by EVP_DecryptFinal_ex()

	EVP_CIPHER_CTX_free(ctx);
	tmp.resize(len);

	return tmp;
}

std::vector<std::uint8_t> client::client_t::hash_information(const std::string_view info,
	const std::vector<std::uint8_t>& salt)
{
	std::vector<std::uint8_t> tmp;
	for (const auto& c : info)
		tmp.emplace_back(static_cast<std::uint8_t>(c));

	return Argon2::Argon2i(tmp, salt, 5, 69874, 1, 32);
}

std::uint32_t client::client_t::encrypt_email(const std::string_view email)
{
	std::vector<std::uint8_t> tmp;
	tmp.reserve(email.length());
	for (const auto& c : email)
		tmp.push_back(static_cast<std::uint8_t>(c));

	this->user.email = this->encrypt_information(tmp, this->get_iv(email), this->get_enckey_inverse(email));

	return 1;
}

std::uint32_t client::client_t::hash_hwid()
{
	const auto hwid = this->get_hwid();
	const auto enc_key = this->get_salt(hwid);
	this->user.hwid = this->hash_information(hwid, enc_key);

	return 1;
}

std::uint32_t client::client_t::hash_password(const std::string_view password, const std::string_view salt)
{
	std::string a;
	a.reserve(salt.length());

	for (const auto& c : client::client_t::get_salt_inverse(salt))
		a.push_back(static_cast<std::int8_t>(c));

	this->user.password = this->hash_information(password, this->get_salt(a));

	return 1;
}

template <typename I>
auto to_hexstr(const I w, const std::size_t hex_len = sizeof(I) << 1)
{
	static auto digits = "0123456789ABCDEF";

	std::string rc(hex_len, '0');

	for (size_t i = 0, j = (hex_len - 1) * 4; i < hex_len; ++i, j -= 4)
		rc[i] = digits[w >> j & 0x0f];

	return rc;
}

std::string bstr_to_string(BSTR bstr)
{
	const auto len = WideCharToMultiByte(CP_UTF8, 0, bstr, -1, nullptr, 0, nullptr, nullptr);
	std::string str(len, '\0');
	WideCharToMultiByte(CP_UTF8, 0, bstr, -1, str.data(), len, nullptr, nullptr);
	return str;
}

auto to_hex(const std::string_view bytes)
{
	std::vector < std::uint8_t> ret;
	if (bytes.size() % 2 != 0)
		throw std::invalid_argument("Hex not valid.");

	for (auto it = bytes.begin(); it != bytes.end(); it += 2) {
		std::string hexbuf{ it, it + 2 };
		ret.push_back(static_cast<std::uint8_t>(std::stoul(hexbuf, nullptr, 16)));
	}
	return ret;
}

std::string client::client_t::get_hwid() const
{
	std::string hwid;
	std::array<int, 4> cpuid_cached{};
	__cpuid(cpuid_cached.data(), static_cast<std::int32_t>(0x80000001));
	cpuid_cached[2] |= 0x8000;

	for (const std::uint32_t cpu_id = std::accumulate(cpuid_cached.begin(), cpuid_cached.end(), 0); const auto& c : {
		static_cast<std::uint8_t>(cpu_id >> 24), static_cast<std::uint8_t>(cpu_id >> 16),
		static_cast<std::uint8_t>(cpu_id >> 8), static_cast<std::uint8_t>(cpu_id)
		})
		hwid.append(to_hexstr(c));

	IWbemLocator* locator_ptr{ nullptr };
	IWbemServices* svc_ptr{ nullptr };
	IEnumWbemClassObject* enumerator_ptr{ nullptr };
	VARIANT variant_prop{};
	IWbemClassObject* wbem_class_object_ptr{ nullptr };
	ULONG fn_return{ 0 };
	HRESULT hr;

	HRESULT hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
	if (hres < 0)
		throw std::runtime_error("COM Initialization failed.");

	hres = CoInitializeSecurity(
		nullptr,
		-1,
		nullptr,
		nullptr,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE,
		nullptr
	);
	if (hres < 0)
		throw std::runtime_error("COM Security Initialization failed.");

	hres = CoCreateInstance(
		CLSID_WbemLocator,
		nullptr,
		CLSCTX_INPROC_SERVER,
		IID_IWbemLocator,
		reinterpret_cast<void**>(&locator_ptr)
	);

	if (hres < 0)
		throw std::runtime_error("IWbemLocator Initialization failed.");

	hres = locator_ptr->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), 
		nullptr, 
		nullptr, 
		nullptr, 
		NULL, 
		nullptr, 
		nullptr, 
		&svc_ptr 
	);
	if (hres < 0)
		throw std::runtime_error("Could not connect to WMI.");

	hres = CoSetProxyBlanket(
		svc_ptr,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		nullptr,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		nullptr,
		EOAC_NONE
	);

	if (hres < 0)
		throw std::runtime_error("Could not set security blanket.");

	hres = svc_ptr->ExecQuery(
		_bstr_t("WQL"),
		_bstr_t("SELECT * FROM Win32_Baseboard"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&enumerator_ptr);

	if (hres < 0)
		throw std::runtime_error("Wmi Query for BB failed.");

	while (enumerator_ptr)
	{
		enumerator_ptr->Next(WBEM_INFINITE, 1,
			&wbem_class_object_ptr, &fn_return);

		if (0 == fn_return)
			break;

		VariantInit(&variant_prop);

		hr = wbem_class_object_ptr->Get(L"SerialNumber", 0, &variant_prop, 0, 0);
		if (hr >= 0)
		{
			hwid.append(bstr_to_string(variant_prop.bstrVal));
			VariantClear(&variant_prop);
		}
		wbem_class_object_ptr->Release();
	}

	hres = svc_ptr->ExecQuery(
		_bstr_t("WQL"),
		_bstr_t("SELECT * FROM Win32_ComputerSystemProduct"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&enumerator_ptr);

	if (hres < 0)
		throw std::runtime_error("Wmi Query for CSP failed.");

	while (enumerator_ptr)
	{
		enumerator_ptr->Next(WBEM_INFINITE, 1,
			&wbem_class_object_ptr, &fn_return);

		if (0 == fn_return)
			break;

		VariantInit(&variant_prop);

		hr = wbem_class_object_ptr->Get(L"UUID", 0, &variant_prop, 0, 0);
		if (hr >= 0)
		{
			hwid.append(bstr_to_string(variant_prop.bstrVal));
			VariantClear(&variant_prop);
		}
		wbem_class_object_ptr->Release();
	}

	hres = svc_ptr->ExecQuery(
		_bstr_t("WQL"),
		_bstr_t("SELECT * FROM Win32_BIOS"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		nullptr,
		&enumerator_ptr);

	if (hres < 0)
		throw std::runtime_error("WMI Query for B failed.");

	while (enumerator_ptr)
	{
		hr = enumerator_ptr->Next(WBEM_INFINITE, 1,
			&wbem_class_object_ptr, &fn_return);

		if (0 == fn_return)
			break;


		VariantInit(&variant_prop);

		hr = wbem_class_object_ptr->Get(L"SerialNumber", 0, &variant_prop, 0, 0);
		if (hr >= 0)
		{
			hwid.append(bstr_to_string(variant_prop.bstrVal));
			VariantClear(&variant_prop);
		}

		wbem_class_object_ptr->Release();
	}

	svc_ptr->Release();
	locator_ptr->Release();
	enumerator_ptr->Release();
	CoUninitialize();

	return hwid;
}

inline client::client_t::authed_user json_to_user(const nlohmann::json& json)
{
	return {
		json["subscription_type"].get<std::uint8_t>(),
		json["is_online"].get<std::uint8_t>(),

		json["user_id"].get<std::uint32_t>(),
		json["unix_time_end"].get<std::int64_t>(),
		json["user"].get<std::string>(),

		to_hex(json["email"].get<std::string>()),
		to_hex(json["password"].get<std::string>()),
		to_hex(json["hwid"].get<std::string>())
	};
}

std::string client::client_t::serialize_user() const
{
	if (this->user.email.size() < 8 or this->user.email.size() > 64 or this->user.hwid.size() != 32 or this->user.
		password.size() != 32 or this->user.user.size() < 4 or this->user.user.size() > 16)
		return "";

	std::string email, password, hwid;

	for (const auto& c : this->user.email)
		email.append(to_hexstr(static_cast<std::int8_t>(c)));
	for (const auto& c : this->user.password)
		password.append(to_hexstr(static_cast<std::int8_t>(c)));
	for (const auto& c : this->user.hwid)
		hwid.append(to_hexstr(static_cast<std::int8_t>(c)));

	const nlohmann::json json_value = {
		{"subscription_type", this->user.subscription_type},
		{"is_online", this->user.is_online},
		{"user_id", this->user.user_id},
		{"unix_time_end", this->user.unix_time_end},
		{"user", this->user.user},
		{"email", email},
		{"password", password},
		{"hwid", hwid}
	};
	return json_value.dump();
}

std::uint32_t client::client_t::get_regkey()
{
	HKEY regkey;
	DWORD disposition;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\example", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &regkey, &disposition))
	{
		RegCloseKey(regkey);
		return 1;
	}

	std::string str(480, '\x0');
	DWORD type = 1u, sz{ 480u };

	if (RegGetValueA(regkey, nullptr, "auth_key", RRF_RT_REG_SZ, &type, str.data(), &sz) == ERROR_SUCCESS)
	{
		this->user = json_to_user(nlohmann::json::parse(str));
		RegCloseKey(regkey);
		return 0;
	}

	RegCloseKey(regkey);
	return 2;
}

std::uint32_t client::client_t::set_regkey(const std::string& serialized)
{
	HKEY regkey;
	DWORD disposition;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\example", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &regkey, &disposition))
	{
		RegCloseKey(regkey);
		return 1;
	}

	if (!RegSetValueExA(regkey, "auth_key", 0, REG_SZ, reinterpret_cast<const BYTE*>(serialized.data()), serialized.length() + 1))
	{
		RegCloseKey(regkey);
		return 0;
	}

	RegCloseKey(regkey);
	return 1;
}


std::uint32_t client::client_t::reflect_user()
{
	const auto serialized = this->serialize_user();
	hv::HttpClient http_client;
	HttpRequest req;
	HttpResponse resp;
	req.method = HTTP_POST;
	req.url = "https://example.site/register";
	req.headers["content-type"] = "application/json";

	req.body = serialized;
	req.timeout = 10;
	http_client.send(&req, &resp);
	if (const auto response_body = nlohmann::json::parse(resp.body); response_body["result"] == "Success")
	{
		this->user = json_to_user(nlohmann::json::parse(response_body["authed_user"].get<std::string>()));
		return 0;
	}
	return resp.status_code;
}

std::uint32_t client::client_t::register_user(const std::string& usr, const std::string& email, const std::string& password)
{
	this->user.user = usr;
	encrypt_email(email);
	hash_password(password, email);
	hash_hwid();
	return register_user();
}

std::uint32_t client::client_t::register_user()
{
	const auto serialized = this->serialize_user();
	hv::HttpClient http_client;
	HttpRequest req;
	HttpResponse resp;
	req.method = HTTP_POST;
	req.url = "https://example.site/register";
	req.headers["content-type"] = "application/json";

	req.body = serialized;
	req.timeout = 10;
	int ret = http_client.send(&req, &resp);

	if (const auto response_body = nlohmann::json::parse(resp.body); response_body["result"] == "Success")
	{
		const auto serialized_resp = response_body["authed_user"].get<std::string>();
		this->user = json_to_user(nlohmann::json::parse(serialized_resp));
		set_regkey(serialized_resp);
		return 0;
	}
	return resp.status_code;
}

std::uint32_t client::client_t::init()
{
	if (const auto ret = this->get_regkey())
		return ret;

	if (const auto status_code = this->reflect_user())
		return status_code; // 

	const auto curr_timestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

	if (const auto hwid = this->get_hwid(); user.hwid != this->hash_information(hwid, this->get_enckey(hwid)))
		return 1; // HWID mismatch

	if (user.subscription_type == 1 and user.unix_time_end == -1)
		return 0; // user authed

	if (user.unix_time_end <= curr_timestamp)
		return 2; // not enough time to be authed

	// maybe add a kill thread or something
	return 0;
}