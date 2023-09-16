window.addEventListener("load", function () {
    const cookies = document.cookie.split(";"); // get all the cookies
    let cookieExists = false;
    cookies.forEach(cookie => {
        const [name, value] = cookie.split("="); // split each cookie into name and value
        if (name.trim() === ".VLVTSECURITY") {
            cookieExists = true;
            return;
        }
    });
    if (cookieExists) {
        window.location.href = "https://example.site/dashboard/"; // redirect to dashboard
    }
});

async function get_enckey(orig_string) {
    var ret = "";

    var left = 0;
    var right = orig_string.length - 1;

    var left_turn = true;

    while (ret.length < 32) {
        if (left > right) {
            left = 0;
            right = orig_string.length - 1;
        }

        ret += (left_turn ? orig_string[left++] : orig_string[right--]);
        left_turn = !left_turn;
    }

    return ret;
}

async function get_enckey_inverse(orig_string) {
    var ret = "";
    var left = 0;
    var right = orig_string.length - 1;
    var right_turn = true;

    while (ret.length < 32) {
        if (left > right) {
            left = 0; right = orig_string.length - 1;
        }

        ret += (right_turn ? orig_string[right--] : orig_string[left++]);
        right_turn = !right_turn;
    }

    return ret;
}

async function get_salt(orig_string) {
    var ret = "";
    var left = 0;
    var right = orig_string.length - 1;

    var left_turn = true;

    while (left <= right) {
        if (left > right) {
            left = 0; right = orig_string.length - 1;
        }
        ret += (left_turn ? orig_string[left++] : orig_string[right--]);
        left_turn = !left_turn
    }
    return ret;
}

async function get_salt_inverse(orig_string) {
    var ret = "";
    var left = 0;
    var right = orig_string.length - 1;

    var right_turn = true;

    while (left <= right) {
        if (left > right) {
            left = 0; right = orig_string.length - 1;
        }
        ret += (right_turn ? orig_string[right--] : orig_string[left++]);
        right_turn = !right_turn
    }

    return ret;
}


async function get_iv(orig_string) {
    var ret = "";
    var left = 0;
    var right = orig_string.length - 1;
    var left_turn = true;

    while (ret.length < 16) {
        if (left > right) {
            left = 0;
            right = orig_string.length - 1;
        }

        ret += (left_turn ? orig_string[left++] : orig_string[right--]);
        left_turn = !left_turn;
    }

    return ret;
}

async function get_iv_inverse(orig_string) {
    var ret = "";
    var left = 0;
    var right = orig_string.length - 1;
    var right_turn = true;

    while (ret.length < 16) {
        if (left > right) {
            left = 0;
            right = orig_string.length - 1;
        }

        ret += (right_turn ? orig_string[right--] : orig_string[left++]);
        right_turn = !right_turn;
    }

    return ret;
}

async function aes256_encrypt(key, plaintext, iv) {
    const encodedKey = new TextEncoder().encode(key);
    const encodedIv = new TextEncoder().encode(iv);
    const encodedPlaintext = new TextEncoder().encode(plaintext);

    const algorithm = {
        name: 'AES-CBC',
        iv: encodedIv
    };

    const keyObject = await crypto.subtle.importKey('raw', encodedKey, algorithm, false, ['encrypt']);

    const encrypted = await crypto.subtle.encrypt(algorithm, keyObject, encodedPlaintext);
    const encryptedArray = new Uint8Array(encrypted);
    const encryptedString = btoa(String.fromCharCode.apply(null, encryptedArray));
    return `${encryptedString}`;
}

async function hash_information(plaintext, key) {
    try {
        const result = await argon2.hash({
            // required
            pass: plaintext,
            salt: key,
            // optional
            time: 5, // the number of iterations
            mem: 69874, // used memory, in KiB
            hashLen: 32, // desired hash length
            parallelism: 1, // desired parallelism (it won't be computed in parallel, however)
            secret: new Uint8Array([]), // optional secret data
            ad: new Uint8Array([]), // optional associated data
            type: argon2.ArgonType.Argon2i, // Argon2d, Argon2i, Argon2id
        });
        return result.hashHex;
    } catch (error) {
        return error.code;
    }
}

async function encrypt_email(email) {
    const iv = await get_iv(email);
    const key = await get_enckey_inverse(email);
    const enc_email = await aes256_encrypt(key, email, iv);
    return enc_email;
}

async function hash_password(email, password) {
    const key_1 = await get_salt_inverse(email);
    const key_2 = await get_salt(key_1);
    const hashed_pwd = await hash_information(password, key_2);
    return hashed_pwd;
}

function serialize_credentials(password, email) {
    var credentials = {
        password: password,
        email: email
    };

    var json = JSON.stringify(credentials);

    return json;
}

function decode64(base64) {
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);

    for (var i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }

    var hex = Array.prototype.map.call(bytes, function (byte) {
        return ('0' + byte.toString(16)).slice(-2);
    }).join('');

    return hex;
}

const email_input = document.getElementById('emailinput');
const pwd_input = document.getElementById('pwdinput');
const login_btn = document.getElementById('login_form');

email_input.addEventListener('input', function () {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const emailValue = email_input.value.trim();
    if (emailValue.length == 0) {
        // valid password length
        email_input.style.boxShadow = '0 0 0px 0px #008000'; // green box shadow
        email_input.style.borderColor = '#ffffff33'; // green border
    }
    else if (emailRegex.test(emailValue)) {
        // valid email format
        email_input.style.boxShadow = '0 0 10px 0px #008000'; // green box shadow
        email_input.style.borderColor = '#008000'; // green border
    } else {
        // invalid email format
        email_input.style.boxShadow = '0 0 10px 0px #B22222'; // red box shadow
        email_input.style.borderColor = '#B22222'; // red border
    }
});

pwd_input.addEventListener('input', function () {
    const pwd_value = pwd_input.value.trim();
    if (pwd_value.length == 0) {
        // valid password length
        pwd_input.style.boxShadow = '0 0 0px 0px #008000'; // green box shadow
        pwd_input.style.borderColor = '#ffffff33'; // green border
    }
    else if (pwd_value.length >= 8 && pwd_value.length <= 32) {
        // valid password length
        pwd_input.style.boxShadow = '0 0 10px 0px #008000'; // green box shadow
        pwd_input.style.borderColor = '#008000'; // green border
    } else {
        // invalid password length
        pwd_input.style.boxShadow = '0 0 10px 0px #B22222'; // red box shadow
        pwd_input.style.borderColor = '#B22222'; // red border
    }
});

login_btn.addEventListener('click', async function () {
    const pwd_value = pwd_input.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    const emailValue = email_input.value.trim();
    const error_msg = document.getElementById('errmsg');
    if (pwd_value.length == 0) {
        error_msg.innerHTML = "Password cannot be empty.";
        return;
    }
    else if (pwd_value.length <= 8 && pwd_value.length >= 32) {
        error_msg.innerHTML = "Password cannot be smaller than 8 characters or larger than 32 characters.";
        return;
    }
    else if (emailValue.length == 0) {
        error_msg.innerHTML = "Email cannot be empty.";
        return;
    }
    else if (!emailRegex.test(emailValue)) {
        error_msg.innerHTML = "Invalid email.";
        return;
    }
    var hashed_password = await hash_password(emailValue, pwd_value);
    var encrypted_email = await encrypt_email(emailValue);
    encrypted_email = decode64(encrypted_email);
    var prepped = serialize_credentials(hashed_password, encrypted_email);

    console.log(prepped);
    var xhr = new XMLHttpRequest();

    xhr.open("POST", "https://example.site/login", true);
    xhr.setRequestHeader("Content-Type", "application/json");
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var response = JSON.parse(xhr.responseText);
            if (response["result"] == "Success") {
                const expiryDate = new Date(Date.now() + (24 * 60 * 60 * 1000)).toUTCString(); // expiry date in 1 hour
                document.cookie = ".EXMPLSECURITY=" + JSON.stringify(response["authed_user"]) + "; expires=" + expiryDate + "; path=/";
            }
        }
    }

    xhr.send(prepped);
});