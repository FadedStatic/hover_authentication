#include "client_clr.hpp"


#pragma comment(lib, "wbemuuid.lib")

std::vector<std::uint8_t> internals::get_enckey(const std::string_view orig_string)
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

std::vector<std::uint8_t> internals::get_enckey_inverse(const std::string_view orig_string)
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

std::vector<std::uint8_t> internals::get_salt(const std::string_view orig_string)
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

std::vector<std::uint8_t> internals::get_salt_inverse(const std::string_view orig_string)
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

		ret.emplace_back(right_turn ? orig_string.at(right--) : orig_string.at(left++));
		right_turn = !right_turn;
	}

	return ret;
}

std::vector<std::uint8_t> internals::get_iv(const std::string_view orig_string)
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

std::vector<std::uint8_t> internals::get_iv_inverse(const std::string_view orig_string)
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

std::vector<std::uint8_t> internals::encrypt_information(const std::vector<std::uint8_t>& info,
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

std::vector<std::uint8_t> internals::decrypt_information(const std::vector<std::uint8_t>& info,
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

std::vector<std::uint8_t> internals::hash_information(const std::string_view info,
	const std::vector<std::uint8_t>& salt)
{
	std::vector<std::uint8_t> tmp;
	for (const auto& c : info)
		tmp.emplace_back(static_cast<std::uint8_t>(c));

	return Argon2::Argon2i(tmp, salt, 5, 69874, 1, 32);
}

std::vector<std::uint8_t> internals::encrypt_email(const std::string_view email)
{
	std::vector<std::uint8_t> tmp;
	tmp.reserve(email.length());
	for (const auto& c : email)
		tmp.push_back(static_cast<std::uint8_t>(c));

	return internals::encrypt_information(tmp, internals::get_iv(email), internals::get_enckey_inverse(email));
}

std::vector<std::uint8_t> internals::hash_hwid()
{
	const auto hwid = internals::get_hwid();
	const auto enc_key = internals::get_salt(hwid);
	return internals::hash_information(hwid, enc_key);
}

std::vector<std::uint8_t> internals::hash_password(const std::string_view password, const std::string_view salt)
{
	std::string a;
	a.reserve(salt.length());

	for (const auto& c : internals::get_salt_inverse(salt))
		a.push_back(static_cast<std::int8_t>(c));

	return internals::hash_information(password, internals::get_salt(a));
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

std::string internals::get_hwid()
{
	std::string hwid;
	std::array<int, 4> cpuid_cached{};
	__cpuid(cpuid_cached.data(), static_cast<std::int32_t>(0x80000001));
	cpuid_cached[2] |= 0x8000;

	const std::uint32_t cpu_id = std::accumulate(cpuid_cached.begin(), cpuid_cached.end(), 0);
	const auto joined_vec = {
		static_cast<std::uint8_t>(cpu_id >> 24), static_cast<std::uint8_t>(cpu_id >> 16),
			static_cast<std::uint8_t>(cpu_id >> 8), static_cast<std::uint8_t>(cpu_id)
	};

	for (const auto& c : joined_vec)
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

internals::authed_user internals::json_to_user(const nlohmann::json& json)
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

std::string internals::serialize_user(const internals::authed_user& usr)
{
	std::string email, password, hwid;

	for (const auto& c : usr.email)
		email.append(to_hexstr(static_cast<std::int8_t>(c)));
	for (const auto& c : usr.password)
		password.append(to_hexstr(static_cast<std::int8_t>(c)));
	for (const auto& c : usr.hwid)
		hwid.append(to_hexstr(static_cast<std::int8_t>(c)));

	const nlohmann::json json_value = {
		{"subscription_type", usr.subscription_type},
		{"is_online", usr.is_online},
		{"user_id", usr.user_id},
		{"unix_time_end", usr.unix_time_end},
		{"user", usr.user},
		{"email", email},
		{"password", password},
		{"hwid", hwid}
	};
	return json_value.dump();
}

internals::authed_user internals::get_regkey()
{
	HKEY regkey;
	DWORD disposition;
	if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\example", 0, nullptr, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, nullptr, &regkey, &disposition))
	{
		RegCloseKey(regkey);
		return {};
	}

	std::string str(480, '\x0');
	DWORD type = 1u, sz{ 480u };

	if (RegGetValueA(regkey, nullptr, "auth_key", RRF_RT_REG_SZ, &type, str.data(), &sz) == ERROR_SUCCESS)
	{
		RegCloseKey(regkey);
		return json_to_user(nlohmann::json::parse(str));
	}

	RegCloseKey(regkey);
	return {};
}

std::uint32_t internals::set_regkey(const std::string& serialized)
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


internals::authed_user internals::reflect_user(const authed_user& usr)
{
	const auto serialized = internals::serialize_user(usr);
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
		return json_to_user(nlohmann::json::parse(response_body["authed_user"].get<std::string>()));
	}
	return {};
}

internals::authed_user internals::register_user(const std::string& usr, const std::string& email, const std::string& password)
{
	authed_user user;
	user.user = usr;
	user.email = encrypt_email(email);
	user.password = hash_password(password, email);
	user.hwid = hash_hwid();
	return internals::register_user(user);
}

internals::authed_user internals::register_user(const internals::authed_user& usr)
{
	const auto serialized = internals::serialize_user(usr);
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
		const auto serialized_resp = response_body["authed_user"].get<std::string>();
		const auto ret = json_to_user(nlohmann::json::parse(serialized_resp));
		set_regkey(serialized_resp);
		return ret;
	}
	return {};
}