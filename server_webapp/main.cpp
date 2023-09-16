#include <drogon/drogon.h>
#include <openssl/aes.h>
#include <chrono>
#include <iostream>

#include <string>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include "auth/include.hpp"

auto base64_encode(const std::string_view bytes_to_encode)
{
	static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	const auto in_len = bytes_to_encode.length();
	std::string ret;
	ret.reserve((in_len + 2) / 3 * 4);

	for (unsigned int i = 0; i < in_len; ++i)
	{
		const unsigned int byte = bytes_to_encode[i];

		switch (i % 3)
		{
		case 0:
			ret.push_back(base64_chars[(byte >> 2) & 0x3F]);
			break;

		case 1:
			ret.push_back(base64_chars[((byte >> 4) & 0x0F) | ((bytes_to_encode[i - 1] << 4) & 0x3F)]);
			break;

		case 2:
			ret.push_back(base64_chars[((byte >> 6) & 0x03) | ((bytes_to_encode[i - 1] << 2) & 0x3F)]);
			ret.push_back(base64_chars[byte & 0x3F]);
			break;

		default:
			break;
		}
	}

	if (in_len % 3 != 0)
		for (unsigned int i = 0; i < 3 - in_len % 3; ++i)
			ret.push_back('=');

	return ret;
}

auto compute_signature(const std::string_view payload, const std::string_view secret)
{
	unsigned char result[EVP_MAX_MD_SIZE];
	unsigned int len = 0;

	HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
		 reinterpret_cast<const unsigned char*>(payload.data()), payload.size(),
		 result, &len);

	std::ostringstream oss;
	oss << std::hex << std::setfill('0');

	for (unsigned int i = 0; i < len; ++i)
		oss << std::setw(2) << static_cast<unsigned int>(result[i]);

	return oss.str();
}

auto parse_header(const std::string& header)
{
	int timestamp = 0;
	std::vector<std::string> signatures;

	std::istringstream iss(header);
	std::string item, key, value;
	std::size_t pos{0};

	while (std::getline(iss, item, ','))
	{
		pos = item.find('=');
		key = item.substr(0, pos), value = item.substr(pos + 1);

		if (key == "t")
			timestamp = std::stoi(value);

		else if (key.substr(0, 1) == "v")
			signatures.push_back(value);
	}

	return std::make_pair(timestamp, signatures);
}

auto verify_header(const std::string& payload, const std::string& header, const std::string& secret,
				   const int tolerance = 0)
{
	auto [timestamp, signatures] = parse_header(header);

	if (signatures.empty())
		return false;

	const auto signed_payload = std::to_string(timestamp) + "." + payload;

	if (const auto expected_sig = compute_signature(signed_payload, secret); std::ranges::none_of(
		signatures.begin(), signatures.end(),
		[&expected_sig](const std::string& s)
		{
			return s == expected_sig;
		}))
		return false;

	if (tolerance && timestamp < time(nullptr) - tolerance)
		return false;

	return true;
}

std::map<std::int32_t, std::string> strstatus = 
{
	{200, "OK"},
	{201, "Created"},
	{204, "No Content"},
	{400, "Bad Request"},
	{401, "Unauthorized"},
	{403, "Forbidden"},
	{404, "Not Found"},
	{500, "Internal Server Error"}
};

inline auto status_code_to_string(const std::int32_t status_code)
{
	return strstatus.contains(status_code) ? strstatus.at(status_code) : "Unknown status code";
}

auto error_handler(const drogon::HttpStatusCode status)
{
	Json::Value ret;
	ret["success"] = false;
	ret["message"] = status_code_to_string(status);

	auto resp = drogon::HttpResponse::newHttpJsonResponse(ret);
	resp->setStatusCode(status);

	return resp;
}

auto pre_route = [](const drogon::HttpRequestPtr& req)
{
	if (auto& path = const_cast<std::string&>(req->path()); path != "/" && path.back() == '/')
		path.pop_back();
};

int main()
{
	// Get database and key ordering.
	const auto db = database::get("usr_auth.hvdb");
	const auto getkey = auth::getkey::get("keys.hvdb");
	
	drogon::app()

	// Set path for logs (must exist before deployment)
	.setLogPath("./drogon_logs")

	.setFileTypes({"html", "js", "png", "css", "jpg", "jpeg", "wasm", "", "avif", "json","woff","ttf","svg","woff2", "ico"})

	// Set root for document access, this is mainly for abstraction.
	.setDocumentRoot("./siteroot")

	// Set listener, this is port 443 as we are using HTTPS and our SSL key and cert goes here. True is for UseSSL.
	.addListener("0.0.0.0", 443, true, "./examplecert.pem", "./examplekey.pem")

	// Set our error handler so that it doesn't return drogon 404.
	.setCustomErrorHandler(error_handler)

	// Pre routing advice so that https://example.com/thing/ is the same thing as https://example.com/thing (this was an issue before)
	.registerPreRoutingAdvice(pre_route)

	// nThreads, change depenndent on server size
	.setThreadNum(0)

	// This is to get user, I just named it this because reflection is better than get lmao
	.registerHandler("/reflect",
		[&](const drogon::HttpRequestPtr& req,
			std::function<void(const drogon::HttpResponsePtr&)>&& callback)
		{
			const auto json_obj = req->getJsonObject().get();
			Json::Value json;

			if (json_obj != nullptr)
				try
				{
					switch (const auto usr = db->get_user(database::json_to_user(*json_obj)); usr.user_id)
					{
					case 0:
						json["result"] = "Error";
						json["message"] = "User is not in database, sorry.";
						break;

					default:
						json["result"] = "Success";
						json["message"] = "User found.";
					// Serialize the user we found.
						json["authed_user"] = database::serialize_user(usr);
						break;
					}
				}

				catch (...)
				{
					json["result"] = "Error";
					json["message"] = "There was an exception.";
				}

			else
			{
				json["result"] = "Error";
				json["message"] = "Bad JSon Object, expected valid JSON got nil.";
			}

			// Send response
			const auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
			callback(resp);
		})

	// Login Endpoint
	.registerHandler("/login",
		[&](const drogon::HttpRequestPtr& req,
			std::function<void(const drogon::HttpResponsePtr&)>&& callback)
		{
			const auto json_obj = req->getJsonObject().get();
			Json::Value json;
			if (json_obj != nullptr)
			{
				try
				{
					switch (const auto usr = db->get_user_by_email(database::json_to_site_user(*json_obj)); usr.
						user_id)
					{
					case 0:
						json["result"] = "Error";
						json["message"] = "User/Password may be incorrect, or is not in our system.";
						break;

					default:
						const auto str = database::serialize_user(usr);
						json["result"] = "Success";
						json["message"] = "User found.";
						// Serialize the user we found.
						json["authed_user"] = str;
						break;
					}
				}

				catch (...)
				{
					json["result"] = "Error";
					json["message"] = "There was an exception.";
				}
			}
			else
			{
				json["result"] = "Error";
				json["message"] = "Bad JSon Object, expected valid JSON got nil.";
			}

			// Send response
			const auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
			callback(resp);
		})

	// Register users, pretty straightforward
	.registerHandler("/register",
		[&](const drogon::HttpRequestPtr& req,
			std::function<void(const drogon::HttpResponsePtr&)>&& callback)
		{
			const auto json_obj = req->getJsonObject().get();
			Json::Value json;

			if (json_obj != nullptr)
				try
				{
					switch (authed_user ret_usr; db->add_entry(database::json_to_user(*json_obj), ret_usr))
					{
					case 1:
						json["result"] = "Error";
						json["message"] = "Username is taken.";
						break;
					case 2:
						json["result"] = "Error";
						json["message"] = "You have already registered for an account with us.";
						break;
					default:
						json["result"] = "Success";
						json["message"] = "You have been registered!";
						json["authed_user"] = database::serialize_user(ret_usr);
						break;
					}
				}
				catch (...)
				{
					json["result"] = "Error";
					json["message"] = "There was an exception.";
				}

			else
			{
				json["result"] = "Error";
				json["message"] = "Bad JSon Object, expected valid JSON got nil.";
			}

			const auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
			callback(resp);
		})

	// You may be asking why the endpoint is so long and random.
	// This is by design, so that people have trouble finding our endpoint with something like a fuzzer.
	.registerHandler(
		"/SGF2ZUZ1bkZpbmRpbmdUaGlzV2ViaG9va0VuZHBvaW50TG9sTm9vYgSGF2ZUZ1bkZpbmRpbmdUaGlzV2ViaG9va0VuZHBvaW50TG9sTm9vYg",
		[&](const drogon::HttpRequestPtr& req,
			std::function<void(const drogon::HttpResponsePtr&)>&& callback)
		{
			const auto json_obj = req->getJsonObject().get();
			Json::Value json;

			if (json_obj != nullptr)
				try
				{
					const auto& key = req->getHeader("Stripe-Signature");
					Json::Reader reader;
					Json::Value val;
					reader.parse(req->getBody().data(), val);

					if (const auto& tobehashed_value = req->getBody().data(); verify_header(
						tobehashed_value, key, "whsec_PUTYOURKEYHERE"))
					{


						json["success"] = true;
						json["message"] = "Auth Success";
						const auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
						callback(resp);
						return;
					}
				}
				catch (...)
				{
				}

			json["success"] = false;
			json["message"] = status_code_to_string(404);

			const auto resp = drogon::HttpResponse::newHttpJsonResponse(json);
			resp->setStatusCode(static_cast<drogon::HttpStatusCode>(404));
			callback(resp);
		})

	.registerHandler("/getkey?token={token}&commit={commit}",
		[&](const drogon::HttpRequestPtr& req,
			std::function<void(const drogon::HttpResponsePtr&)>&& callback, const std::string& token, const std::string& commit)
		{
			static const auto linkvertise_id = "ID HERE";
			static const auto monetization_link = "MONETIZATION LINK HERE";

			const auto resp = drogon::HttpResponse::newHttpResponse();

			Json::Value json;

			const auto& req_headers = req->getHeaders();

			std::string referer;

			for (const auto& [i,v] : req_headers)
				if (i == "referer")
					referer = v;
			
			const trantor::InetAddress& peer_addr = req->getPeerAddr();
			const std::string client_ip = peer_addr.toIp();
			unsigned char digest[SHA_DIGEST_LENGTH]{0};
			SHA1(reinterpret_cast<const unsigned char*>(client_ip.c_str()), client_ip.length(), digest);

			std::string thing;
			for (const auto& c : digest)
				thing.append(database::to_hexstr(static_cast<std::int8_t>(c)));

			if (!token.empty())
			{
				if (referer == "https://linkvertise.com/")
				{
					if (const auto iter = std::ranges::find_if(getkey->sessions.begin(), getkey->sessions.end(), [&](const auth::getkey::usr_session& c) {
						return c.hash == thing;
						}); iter != getkey->sessions.end())
					{
						switch (iter->stage_ct)
						{
						case 1:
							resp->setBody(std::string(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><meta content="width=device-width,initial-scale=1,shrink-to-fit=no"name=viewport><title>Example Website Name</title><meta content="Example Website Name"name=twitter:title><meta content=https://example.site/assets/img/vltlogo.png name=twitter:image><meta content=website property=og:type><meta content="Put your example text here."name=description><meta content=https://example.site/assets/img/vltlogo.png property=og:image><meta content=summary_large_image name=twitter:card><meta content="Put your example text here."name=twitter:description><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/bootstrap/css/bootstrap.min.css rel=stylesheet><link href="https://fonts.googleapis.com/css?family=Poppins:400,500,700&display=swap"rel=stylesheet><link href=assets/css/particles.css rel=stylesheet><link href=assets/css/styles.css rel=stylesheet><body id=particles-js style=width:100%;height:100%;background:#09090c><nav class="navbar navbar-expand-md navbar-light"style=padding-top:18px;padding-bottom:18px;width:100%><div class=container-fluid><a class=navbar-brand href=# style=color:#fff;margin-left:18px;font-family:poppins id=example_head>example</a><button class=navbar-toggler data-bs-target=#navcol-1 data-bs-toggle=collapse style=margin-left:3px><span class=visually-hidden>Toggle navigation</span><span class=navbar-toggler-icon style="--bs-navbar-toggler-icon-bg:url(&#34;data:image/svg+xml,%3csvg xmlns='https://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(255, 255, 255, 1)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e&#34;)!important"></span></button><div class="collapse navbar-collapse"id=navcol-1><ul class="ms-auto navbar-nav"><li class=nav-item><a class="nav-link active"href=# style=color:#fff;padding-right:18px;font-family:Poppins;font-size:16.5px;margin-left:18px>Home</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-right:18px;padding-left:18px;font-size:16.5px;font-family:Poppins>Download</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-left:18px;padding-right:18px;font-size:16.5px;font-family:Poppins>Documentation</a></ul></div></div></nav><div style="width:406px;height:262px;display:block;position:absolute;top:50%;left:50%;margin-left:-203px;margin-top:-77.5px;color:#fff;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px"><p style=position:relative;margin-right:auto;margin-left:auto;width:63px;font-family:Poppins;margin-top:31px>Get Key<p style=position:relative;margin-right:auto;margin-left:auto;width:102px;font-family:Poppins;margin-top:-17px>Checkpoint 1<p style=position:relative;margin-right:auto;margin-left:auto;width:283px;font-family:Poppins;margin-top:-8px;font-size:11px;color:rgba(255,255,255,.5)>Checkpoint 1 of )") + std::to_string(iter->commit_ct) + std::string(R"(. Proceed through ads to continue.<div class=shidiv id=hc_container></div></div><script src=assets/bootstrap/js/bootstrap.min.js></script><script src=https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js></script><script src=https://js.hcaptcha.com/1/api.js></script><script src=assets/js/particles.js></script><script>function redirectTo(e){window.location.href=e}var hcaptchaCallback=function(e){e&&0<e.length&&setTimeout(function(){redirectTo(")") + monetization_link + std::string(R"(")},1e3)};hcaptcha.render("hc_container",{sitekey:"9edb679b-7b45-4361-937b-4ac9286f67e0",callback:hcaptchaCallback,theme:"dark"})</script>)"));
							break;

						case 2:
						case 3:
						case 4:
							// seems normal, let's send them forward.
							break;

						case 5:
							// okay we're done here.
							break;
						default:break;
						}
					}

					else if (iter == getkey->sessions.end())
					{
						// send them back in time...
					}
				}
			}

			if (referer.contains("monetization.click") or referer.contains("monetization.site"))
			{
				if (const auto iter = std::ranges::find_if(getkey->sessions.begin(), getkey->sessions.end(), [&](const auth::getkey::usr_session& c) {
					return c.hash == thing;
					}); iter != getkey->sessions.end() or (getkey->sessions.size() == 1))
				{
					if (getkey->sessions.end()->hash != thing)
						goto kerbobble2;

					switch (iter->stage_ct)
					{
					case 1:
						std::cout << static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp << "\r\n";
						if (static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp < 15)
						{
							resp->setBody(R"(<!doctypehtml><html lang=en style="width:100%; height:100%"><meta charset=utf-8><body><a>wesley stubbed his toe.</a></body>)");
						}
						else if (static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp > 15)
						{
							std::string secret, tmp, num_sc;

							long double random_number;
							long double scaled_number;
							std::stringstream stream{};

							std::srand(static_cast<std::uint32_t>(std::time(nullptr)) + 3120391u);
							secret = auth::getkey::random_string(16);

							random_number = std::rand() / static_cast<long double>(RAND_MAX); // generate a random number between 0 and 1
							scaled_number = random_number * 1000; // scale the random number to be between 0 and 1000

							stream << std::fixed << std::setprecision(13) << scaled_number;
							num_sc = stream.str();

							tmp =
								std::string("https://link-to.net/") + linkvertise_id + "/" + num_sc +
								"/dynamic/?r=" + base64_encode("https://example.site/getkey?token=" + secret);

							resp->setBody(std::string(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><meta content="width=device-width,initial-scale=1,shrink-to-fit=no"name=viewport><title>Example Website Name</title><meta content="Example Website Name"name=twitter:title><meta content=https://example.site/assets/img/vltlogo.png name=twitter:image><meta content=website property=og:type><meta content="Put your example text here."name=description><meta content=https://example.site/assets/img/vltlogo.png property=og:image><meta content=summary_large_image name=twitter:card><meta content="Put your example text here."name=twitter:description><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/bootstrap/css/bootstrap.min.css rel=stylesheet><link href="https://fonts.googleapis.com/css?family=Poppins:400,500,700&display=swap"rel=stylesheet><link href=assets/css/particles.css rel=stylesheet><link href=assets/css/styles.css rel=stylesheet><body id=particles-js style=width:100%;height:100%;background:#09090c><nav class="navbar navbar-expand-md navbar-light"style=padding-top:18px;padding-bottom:18px;width:100%><div class=container-fluid><a class=navbar-brand href=# style=color:#fff;margin-left:18px;font-family:poppins id=example_head>example</a><button class=navbar-toggler data-bs-target=#navcol-1 data-bs-toggle=collapse style=margin-left:3px><span class=visually-hidden>Toggle navigation</span><span class=navbar-toggler-icon style="--bs-navbar-toggler-icon-bg:url(&#34;data:image/svg+xml,%3csvg xmlns='https://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(255, 255, 255, 1)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e&#34;)!important"></span></button><div class="collapse navbar-collapse"id=navcol-1><ul class="ms-auto navbar-nav"><li class=nav-item><a class="nav-link active"href=# style=color:#fff;padding-right:18px;font-family:Poppins;font-size:16.5px;margin-left:18px>Home</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-right:18px;padding-left:18px;font-size:16.5px;font-family:Poppins>Download</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-left:18px;padding-right:18px;font-size:16.5px;font-family:Poppins>Documentation</a></ul></div></div></nav><div style="width:406px;height:262px;display:block;position:absolute;top:50%;left:50%;margin-left:-203px;margin-top:-77.5px;color:#fff;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px"><p style=position:relative;margin-right:auto;margin-left:auto;width:63px;font-family:Poppins;margin-top:31px>Get Key<p style=position:relative;margin-right:auto;margin-left:auto;width:102px;font-family:Poppins;margin-top:-17px>Checkpoint 1<p style=position:relative;margin-right:auto;margin-left:auto;width:283px;font-family:Poppins;margin-top:-8px;font-size:11px;color:rgba(255,255,255,.5)>Checkpoint )" + std::to_string(iter->stage_ct+1) + " of " + std::to_string(iter->commit_ct) + R"(. Proceed through ads to continue.<div class = "shidiv" id = "hc_container"></div></div><script src = "assets/bootstrap/js/bootstrap.min.js"></script><script src = https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js></script><script src=https://js.hcaptcha.com/1/api.js></script><script src=assets/js/particles.js></script><script>function redirectTo(e){window.location.href=e}var hcaptchaCallback=function(e){e&&0<e.length&&setTimeout(function(){redirectTo(")") + tmp + std::string(R"(")},1e3)};hcaptcha.render("hc_container",{sitekey:"9edb679b-7b45-4361-937b-4ac9286f67e0",callback:hcaptchaCallback,theme:"dark"})</script>)"));
							iter->stage_ct++;
						}
						break;

					case 2:
					case 3:
					case 4:
						resp->setBody(std::string(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><meta content="width=device-width,initial-scale=1,shrink-to-fit=no"name=viewport><title>Example Website Name</title><meta content="Example Website Name"name=twitter:title><meta content=https://example.site/assets/img/vltlogo.png name=twitter:image><meta content=website property=og:type><meta content="Put your example text here."name=description><meta content=https://example.site/assets/img/vltlogo.png property=og:image><meta content=summary_large_image name=twitter:card><meta content="Put your example text here."name=twitter:description><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/bootstrap/css/bootstrap.min.css rel=stylesheet><link href="https://fonts.googleapis.com/css?family=Poppins:400,500,700&display=swap"rel=stylesheet><link href=assets/css/particles.css rel=stylesheet><link href=assets/css/styles.css rel=stylesheet><body id=particles-js style=width:100%;height:100%;background:#09090c><nav class="navbar navbar-expand-md navbar-light"style=padding-top:18px;padding-bottom:18px;width:100%><div class=container-fluid><a class=navbar-brand href=# style=color:#fff;margin-left:18px;font-family:poppins id=example_head>example</a><button class=navbar-toggler data-bs-target=#navcol-1 data-bs-toggle=collapse style=margin-left:3px><span class=visually-hidden>Toggle navigation</span><span class=navbar-toggler-icon style="--bs-navbar-toggler-icon-bg:url(&#34;data:image/svg+xml,%3csvg xmlns='https://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(255, 255, 255, 1)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e&#34;)!important"></span></button><div class="collapse navbar-collapse"id=navcol-1><ul class="ms-auto navbar-nav"><li class=nav-item><a class="nav-link active"href=# style=color:#fff;padding-right:18px;font-family:Poppins;font-size:16.5px;margin-left:18px>Home</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-right:18px;padding-left:18px;font-size:16.5px;font-family:Poppins>Download</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-left:18px;padding-right:18px;font-size:16.5px;font-family:Poppins>Documentation</a></ul></div></div></nav><div style="width:406px;height:262px;display:block;position:absolute;top:50%;left:50%;margin-left:-203px;margin-top:-77.5px;color:#fff;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px"><p style=position:relative;margin-right:auto;margin-left:auto;width:63px;font-family:Poppins;margin-top:31px>Get Key<p style=position:relative;margin-right:auto;margin-left:auto;width:102px;font-family:Poppins;margin-top:-17px>Checkpoint 1<p style=position:relative;margin-right:auto;margin-left:auto;width:283px;font-family:Poppins;margin-top:-8px;font-size:11px;color:rgba(255,255,255,.5)>Checkpoint 1 of 4. Proceed through ads to continue.<div class=shidiv id=hc_container></div></div><script src=assets/bootstrap/js/bootstrap.min.js></script><script src=https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js></script><script src=https://js.hcaptcha.com/1/api.js></script><script src=assets/js/particles.js></script><script>function redirectTo(e){window.location.href=e}var hcaptchaCallback=function(e){e&&0<e.length&&setTimeout(function(){redirectTo(")") + monetization_link + std::string(R"(")},1e3)};hcaptcha.render("hc_container",{sitekey:"9edb679b-7b45-4361-937b-4ac9286f67e0",callback:hcaptchaCallback,theme:"dark"})</script>)"));
						iter->stage_ct = 1;
						break;

					case 5:
						// this should never happen...
						break;
					default:break;
					}
				}

				else if (iter == getkey->sessions.end() and iter->hash != thing)
				{
					kerbobble2:
					// send them back in time...
				}
			}

			if (!commit.empty())
			{
				if (const auto commit_n = static_cast<std::uint8_t>(std::stoi(commit)); commit_n < 5 and commit_n > 1)
				{
					if (const auto iter = std::ranges::find_if(getkey->sessions.begin(), getkey->sessions.end(), [&](const auth::getkey::usr_session& c) {
						return c.hash == thing;
						}); iter != getkey->sessions.end() or (getkey->sessions.size() == 1))
					{
						if (getkey->sessions.end()->hash != thing)
							goto kerbobble1;
						std::string secret, tmp, num_sc;

						long double random_number;
						long double scaled_number;
						std::stringstream stream{};

						switch (iter->stage_ct)
						{
						case 1:
							if (static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp < 15)
							{
								resp->setBody(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><body><a>wesley stubbed his toe.</a></body>)");
							}
							else if (static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp > 15)
							{
								if (static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp < 15)
								{
									resp->setBody(R"(<!doctypehtml><html lang=en style="width:100%; height:100%"><meta charset=utf-8><body><a>wesley stubbed his toe.</a></body>)");
								}
								else if (static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - iter->previous_timestamp > 15)
								{
									std::srand(static_cast<std::uint32_t>(std::time(nullptr)) + 3120391u);
									secret = auth::getkey::random_string(16);

									random_number = std::rand() / static_cast<long double>(RAND_MAX); // generate a random number between 0 and 1
									scaled_number = random_number * 1000; // scale the random number to be between 0 and 1000

									stream << std::fixed << std::setprecision(13) << scaled_number;
									num_sc = stream.str();

									tmp =
										std::string("https://link-to.net/") + linkvertise_id + "/" + num_sc +
										"/dynamic/?r=" + base64_encode("https://example.site/getkey?token=" + secret);
									resp->setBody(std::string(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><meta content="width=device-width,initial-scale=1,shrink-to-fit=no"name=viewport><title>Example Website Name</title><meta content="Example Website Name"name=twitter:title><meta content=https://example.site/assets/img/vltlogo.png name=twitter:image><meta content=website property=og:type><meta content="Put your example text here."name=description><meta content=https://example.site/assets/img/vltlogo.png property=og:image><meta content=summary_large_image name=twitter:card><meta content="Put your example text here."name=twitter:description><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/bootstrap/css/bootstrap.min.css rel=stylesheet><link href="https://fonts.googleapis.com/css?family=Poppins:400,500,700&display=swap"rel=stylesheet><link href=assets/css/particles.css rel=stylesheet><link href=assets/css/styles.css rel=stylesheet><body id=particles-js style=width:100%;height:100%;background:#09090c><nav class="navbar navbar-expand-md navbar-light"style=padding-top:18px;padding-bottom:18px;width:100%><div class=container-fluid><a class=navbar-brand href=# style=color:#fff;margin-left:18px;font-family:poppins id=example_head>example</a><button class=navbar-toggler data-bs-target=#navcol-1 data-bs-toggle=collapse style=margin-left:3px><span class=visually-hidden>Toggle navigation</span><span class=navbar-toggler-icon style="--bs-navbar-toggler-icon-bg:url(&#34;data:image/svg+xml,%3csvg xmlns='https://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(255, 255, 255, 1)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e&#34;)!important"></span></button><div class="collapse navbar-collapse"id=navcol-1><ul class="ms-auto navbar-nav"><li class=nav-item><a class="nav-link active"href=# style=color:#fff;padding-right:18px;font-family:Poppins;font-size:16.5px;margin-left:18px>Home</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-right:18px;padding-left:18px;font-size:16.5px;font-family:Poppins>Download</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-left:18px;padding-right:18px;font-size:16.5px;font-family:Poppins>Documentation</a></ul></div></div></nav><div style="width:406px;height:262px;display:block;position:absolute;top:50%;left:50%;margin-left:-203px;margin-top:-77.5px;color:#fff;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px"><p style=position:relative;margin-right:auto;margin-left:auto;width:63px;font-family:Poppins;margin-top:31px>Get Key<p style=position:relative;margin-right:auto;margin-left:auto;width:102px;font-family:Poppins;margin-top:-17px>Checkpoint 1<p style=position:relative;margin-right:auto;margin-left:auto;width:283px;font-family:Poppins;margin-top:-8px;font-size:11px;color:rgba(255,255,255,.5)>Checkpoint )" + std::to_string(iter->stage_ct + 1) + " of " + std::to_string(iter->commit_ct) + R"(. Proceed through ads to continue.<div class = "shidiv" id = "hc_container"></div></div><script src = "assets/bootstrap/js/bootstrap.min.js"></script><script src = https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js></script><script src=https://js.hcaptcha.com/1/api.js></script><script src=assets/js/particles.js></script><script>function redirectTo(e){window.location.href=e}var hcaptchaCallback=function(e){e&&0<e.length&&setTimeout(function(){redirectTo(")") + tmp + std::string(R"(")},1e3)};hcaptcha.render("hc_container",{sitekey:"9edb679b-7b45-4361-937b-4ac9286f67e0",callback:hcaptchaCallback,theme:"dark"})</script>)"));
									iter->stage_ct++;
								}
							}
							break;

						case 2:
						case 3:
						case 4:
							std::srand(static_cast<std::uint32_t>(std::time(nullptr)) + 3120391u);
							secret = auth::getkey::random_string(16);

							random_number = std::rand() / static_cast<long double>(RAND_MAX); // generate a random number between 0 and 1
							scaled_number = random_number * 1000; // scale the random number to be between 0 and 1000

							stream << std::fixed << std::setprecision(13) << scaled_number;
							num_sc = stream.str();

							tmp =
								std::string("https://link-to.net/") + linkvertise_id + "/" + num_sc +
								"/dynamic/?r=" + base64_encode("https://example.site/getkey?token=" + secret);

							resp->setBody(std::string(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><meta content="width=device-width,initial-scale=1,shrink-to-fit=no"name=viewport><title>Example Website Name</title><meta content="Example Website Name"name=twitter:title><meta content=https://example.site/assets/img/vltlogo.png name=twitter:image><meta content=website property=og:type><meta content="Put your example text here."name=description><meta content=https://example.site/assets/img/vltlogo.png property=og:image><meta content=summary_large_image name=twitter:card><meta content="Put your example text here."name=twitter:description><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/bootstrap/css/bootstrap.min.css rel=stylesheet><link href="https://fonts.googleapis.com/css?family=Poppins:400,500,700&display=swap"rel=stylesheet><link href=assets/css/particles.css rel=stylesheet><link href=assets/css/styles.css rel=stylesheet><body id=particles-js style=width:100%;height:100%;background:#09090c><nav class="navbar navbar-expand-md navbar-light"style=padding-top:18px;padding-bottom:18px;width:100%><div class=container-fluid><a class=navbar-brand href=# style=color:#fff;margin-left:18px;font-family:poppins id=example_head>example</a><button class=navbar-toggler data-bs-target=#navcol-1 data-bs-toggle=collapse style=margin-left:3px><span class=visually-hidden>Toggle navigation</span><span class=navbar-toggler-icon style="--bs-navbar-toggler-icon-bg:url(&#34;data:image/svg+xml,%3csvg xmlns='https://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(255, 255, 255, 1)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e&#34;)!important"></span></button><div class="collapse navbar-collapse"id=navcol-1><ul class="ms-auto navbar-nav"><li class=nav-item><a class="nav-link active"href=# style=color:#fff;padding-right:18px;font-family:Poppins;font-size:16.5px;margin-left:18px>Home</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-right:18px;padding-left:18px;font-size:16.5px;font-family:Poppins>Download</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-left:18px;padding-right:18px;font-size:16.5px;font-family:Poppins>Documentation</a></ul></div></div></nav><div style="width:406px;height:262px;display:block;position:absolute;top:50%;left:50%;margin-left:-203px;margin-top:-77.5px;color:#fff;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px"><p style=position:relative;margin-right:auto;margin-left:auto;width:63px;font-family:Poppins;margin-top:31px>Get Key<p style=position:relative;margin-right:auto;margin-left:auto;width:102px;font-family:Poppins;margin-top:-17px>Checkpoint 1<p style=position:relative;margin-right:auto;margin-left:auto;width:283px;font-family:Poppins;margin-top:-8px;font-size:11px;color:rgba(255,255,255,.5)>Checkpoint )" + std::to_string(iter->stage_ct + 1) + " of " + std::to_string(iter->commit_ct) + R"(. Proceed through ads to continue.<div class = "shidiv" id = "hc_container"></div></div><script src = "assets/bootstrap/js/bootstrap.min.js"></script><script src = "https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js"></script><script src=https://js.hcaptcha.com/1/api.js></script><script src=assets/js/particles.js></script><script>function redirectTo(e){window.location.href=e}var hcaptchaCallback=function(e){e&&0<e.length&&setTimeout(function(){redirectTo(")") + tmp + std::string(R"(")},1e3)};hcaptcha.render("hc_container",{sitekey:"9edb679b-7b45-4361-937b-4ac9286f67e0",callback:hcaptchaCallback,theme:"dark"})</script>)"));
							iter->stage_ct++;
							break;

						case 5:
							// send them the key
							break;
						default:break;
						}

					}
					else if (iter == getkey->sessions.end())
					{
						kerbobble1:
						getkey->sessions.push_back({ 1,commit_n,static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()),{},thing });
						resp->setBody(std::string(R"(<!doctypehtml><html lang=en style="width:100%;height:100%"><meta charset=utf-8><meta content="width=device-width,initial-scale=1,shrink-to-fit=no"name=viewport><title>Example Website Name</title><meta content="Example Website Name"name=twitter:title><meta content=https://example.site/assets/img/vltlogo.png name=twitter:image><meta content=website property=og:type><meta content="Put your example text here."name=description><meta content=https://example.site/assets/img/vltlogo.png property=og:image><meta content=summary_large_image name=twitter:card><meta content="Put your example text here."name=twitter:description><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/img/vltlogo.png rel=icon sizes=842x842 type=image/png><link href=assets/bootstrap/css/bootstrap.min.css rel=stylesheet><link href="https://fonts.googleapis.com/css?family=Poppins:400,500,700&display=swap"rel=stylesheet><link href=assets/css/particles.css rel=stylesheet><link href=assets/css/styles.css rel=stylesheet><body id=particles-js style=width:100%;height:100%;background:#09090c><nav class="navbar navbar-expand-md navbar-light"style=padding-top:18px;padding-bottom:18px;width:100%><div class=container-fluid><a class=navbar-brand href=# style=color:#fff;margin-left:18px;font-family:poppins id=example_head>example</a><button class=navbar-toggler data-bs-target=#navcol-1 data-bs-toggle=collapse style=margin-left:3px><span class=visually-hidden>Toggle navigation</span><span class=navbar-toggler-icon style="--bs-navbar-toggler-icon-bg:url(&#34;data:image/svg+xml,%3csvg xmlns='https://www.w3.org/2000/svg' viewBox='0 0 30 30'%3e%3cpath stroke='rgba(255, 255, 255, 1)' stroke-linecap='round' stroke-miterlimit='10' stroke-width='2' d='M4 7h22M4 15h22M4 23h22'/%3e%3c/svg%3e&#34;)!important"></span></button><div class="collapse navbar-collapse"id=navcol-1><ul class="ms-auto navbar-nav"><li class=nav-item><a class="nav-link active"href=# style=color:#fff;padding-right:18px;font-family:Poppins;font-size:16.5px;margin-left:18px>Home</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-right:18px;padding-left:18px;font-size:16.5px;font-family:Poppins>Download</a><li class=nav-item><a class=nav-link href=# style=color:#fff;padding-left:18px;padding-right:18px;font-size:16.5px;font-family:Poppins>Documentation</a></ul></div></div></nav><div style="width:406px;height:262px;display:block;position:absolute;top:50%;left:50%;margin-left:-203px;margin-top:-77.5px;color:#fff;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.1);border-radius:20px"><p style=position:relative;margin-right:auto;margin-left:auto;width:63px;font-family:Poppins;margin-top:31px>Get Key<p style=position:relative;margin-right:auto;margin-left:auto;width:102px;font-family:Poppins;margin-top:-17px>Checkpoint 1<p style=position:relative;margin-right:auto;margin-left:auto;width:283px;font-family:Poppins;margin-top:-8px;font-size:11px;color:rgba(255,255,255,.5)>Checkpoint 1 of )") + std::to_string(commit_n) + std::string(R"(. Proceed through ads to continue.<div class=shidiv id=hc_container></div></div><script src=assets/bootstrap/js/bootstrap.min.js></script><script src=https://cdn.jsdelivr.net/particles.js/2.0.0/particles.min.js></script><script src=https://js.hcaptcha.com/1/api.js></script><script src=assets/js/particles.js></script><script>function redirectTo(e){window.location.href=e}var hcaptchaCallback=function(e){e&&0<e.length&&setTimeout(function(){redirectTo(")") + monetization_link + std::string(R"(")},1e3)};hcaptcha.render("hc_container",{sitekey:"9edb679b-7b45-4361-937b-4ac9286f67e0",callback:hcaptchaCallback,theme:"dark"})</script>)"));
					}
				}
			}

			callback(resp);
		})
	// Run the app
	.run();
}