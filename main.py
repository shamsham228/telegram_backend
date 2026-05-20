from flask import (
    Flask,
    request,
    jsonify,
    g
)

import requests
import random
import time
import threading
import os

from security.auth_middleware import (
    AuthMiddleware
)

from security.request_verifier import (
    RequestVerifier
)

from security.refresh_handler import (
    RefreshHandler
)

from security.session_store import (
    register_session,
    validate_session,
    revoke_session
)

from security.fraud_detector import (
    record_failure,
    clear_failures,
    is_blocked
)

from security.otp_store import (
    OtpStore
)

app = Flask(__name__)

# --------------------------------
# ENV
# --------------------------------

BOT_TOKEN = os.getenv(
    "BOT_TOKEN"
)

BASE_URL = (

    f"https://api.telegram.org/"
    f"bot{BOT_TOKEN}"
)

# --------------------------------
# USERS
# --------------------------------

users = {}

# --------------------------------
# SECURE REQUEST VERIFICATION
# --------------------------------

def verify_secure_request():

    ip = request.remote_addr

    # --------------------------------
    # BLOCKED IP
    # --------------------------------

    if is_blocked(ip):

        return jsonify({

            "success": False,

            "message":
                "Too many failed requests"

        }), 429

    # --------------------------------
    # HEADERS
    # --------------------------------

    timestamp = request.headers.get(
        "X-Timestamp"
    )

    nonce = request.headers.get(
        "X-Nonce"
    )

    signature = request.headers.get(
        "X-Signature"
    )

    access_token = request.headers.get(
        "Authorization"
    )

    device_id = request.headers.get(
        "X-Device-ID"
    )

    # --------------------------------
    # EMPTY CHECK
    # --------------------------------

    if (

        not timestamp or
        not nonce or
        not signature or
        not access_token or
        not device_id

    ):

        record_failure(ip)

        return jsonify({

            "success": False,

            "message":
                "Missing security headers"

        }), 403

    # --------------------------------
    # REQUEST BODY
    # --------------------------------

    body = request.get_data(
        as_text=True
    )

    # --------------------------------
    # VERIFY REQUEST
    # --------------------------------

    valid = (

        RequestVerifier
        .verify_request(

            body=body,

            timestamp=timestamp,

            nonce=nonce,

            device_id=device_id,

            access_token=access_token,

            received_signature=signature
        )
    )

    # --------------------------------
    # INVALID REQUEST
    # --------------------------------

    if not valid:

        record_failure(ip)

        return jsonify({

            "success": False,

            "message":
                "Invalid secure request"

        }), 403

    # --------------------------------
    # RESET FAILURES
    # --------------------------------

    clear_failures(ip)

    return None

# --------------------------------
# TELEGRAM WEBHOOK
# --------------------------------

@app.route(

    "/telegram",

    methods=["POST"]
)
def telegram_webhook():

    data = request.json

    if (

        not data or
        "message" not in data

    ):

        return "ok"

    message = data["message"]

    chat_id = message["chat"]["id"]

    username = (

        message["from"]
        .get(
            "username",
            ""
        )
        .lower()
    )

    first_name = message["from"].get(
        "first_name",
        ""
    )

    text = message.get(
        "text",
        ""
    )

    # --------------------------------
    # START
    # --------------------------------

    if text == "/start":

        users[chat_id] = {

            "chat_id":
                chat_id,

            "username":
                username,

            "first_name":
                first_name,

            "phone":
                ""
        }

        requests.post(

            f"{BASE_URL}/sendMessage",

            json={

                "chat_id": chat_id,

                "text":

                    f"Connected Successfully\n\n"

                    f"Username: @{username}\n"

                    f"ID: {chat_id}\n"

                    f"First Name: {first_name}\n\n"

                    f"Press button below "
                    f"to share your phone number.",

                "reply_markup": {

                    "keyboard": [

                        [
                            {
                                "text":
                                    "Share Phone Number",

                                "request_contact":
                                    True
                            }
                        ]
                    ],

                    "resize_keyboard":
                        True,

                    "one_time_keyboard":
                        True
                }
            }
        )

    # --------------------------------
    # SAVE CONTACT
    # --------------------------------

    if "contact" in message:

        phone = (

            message["contact"][
                "phone_number"
            ]
        )

        if chat_id in users:

            users[chat_id][
                "phone"
            ] = phone

        requests.post(

            f"{BASE_URL}/sendMessage",

            json={

                "chat_id": chat_id,

                "text":

                    "Phone number saved successfully.\n\n"

                    "You can now login "
                    "inside NetBridge."
            }
        )

    return "ok"

# --------------------------------
# FIND USER
# --------------------------------

def find_user(identifier):

    clean_identifier = (

        identifier
        .replace("@", "")
        .replace("+", "")
        .lower()
    )

    for user in users.values():

        saved_username = (

            user.get(
                "username",
                ""
            )
            .lower()
        )

        saved_phone = (

            user.get(
                "phone",
                ""
            )
            .replace("+", "")
        )

        if (

            saved_username ==
            clean_identifier

            or

            saved_phone ==
            clean_identifier
        ):

            return user

    return None

# --------------------------------
# SEND OTP
# --------------------------------

@app.route(

    "/send_otp",

    methods=["POST"]
)
def send_otp():

    secure = verify_secure_request()

    if secure:
        return secure

    data = request.json

    identifier = data.get(
        "identifier",
        ""
    )

    matched_user = find_user(
        identifier
    )

    # --------------------------------
    # USER NOT FOUND
    # --------------------------------

    if matched_user is None:

        return jsonify({

            "success": False,

            "message":

                "User not found.\n"

                "Open Telegram bot "
                "and press /start first."
        })

    chat_id = matched_user[
        "chat_id"
    ]

    # --------------------------------
    # GENERATE OTP
    # --------------------------------

    otp = str(

        random.randint(

            100000,

            999999
        )
    )

    # --------------------------------
    # SAVE OTP IN REDIS
    # --------------------------------

    OtpStore.save_otp(

        chat_id=chat_id,

        otp=otp,

        expiry_seconds=35
    )

    # --------------------------------
    # SEND TELEGRAM MESSAGE
    # --------------------------------

    response = requests.post(

        f"{BASE_URL}/sendMessage",

        json={

            "chat_id": chat_id,

            "text":

                f"🔐 NetBridge OTP Verification\n\n"

                f"OTP Code: {otp}\n\n"

                f"Expires in 35 seconds.\n\n"

                f"Do NOT share this code."
        }

    ).json()

    # --------------------------------
    # MESSAGE ID
    # --------------------------------

    message_id = (

        response
        .get(
            "result",
            {}
        )
        .get(
            "message_id"
        )
    )

    # --------------------------------
    # AUTO DELETE OTP
    # --------------------------------

    def delete_message():

        time.sleep(35)

        try:

            if message_id:

                requests.post(

                    f"{BASE_URL}/deleteMessage",

                    json={

                        "chat_id":
                            chat_id,

                        "message_id":
                            message_id
                    }
                )

        except Exception:
            pass

    threading.Thread(

        target=delete_message,

        daemon=True

    ).start()

    return jsonify({

        "success": True
    })

# --------------------------------
# VERIFY OTP
# --------------------------------

@app.route(

    "/verify_otp",

    methods=["POST"]
)
def verify_otp():

    secure = verify_secure_request()

    if secure:
        return secure

    data = request.json

    identifier = data.get(
        "identifier",
        ""
    )

    otp = data.get(
        "otp",
        ""
    )

    matched_user = find_user(
        identifier
    )

    if matched_user is None:

        return jsonify({

            "success": False,

            "message":
                "User not found"
        })

    chat_id = matched_user[
        "chat_id"
    ]

    # --------------------------------
    # GET OTP FROM REDIS
    # --------------------------------

    saved = OtpStore.get_otp(
        chat_id
    )

    if not saved:

        return jsonify({

            "success": False,

            "message":
                "OTP expired"
        })

    # --------------------------------
    # INVALID OTP
    # --------------------------------

    if saved["otp"] != otp:

        return jsonify({

            "success": False,

            "message":
                "Invalid OTP"
        })

    # --------------------------------
    # DELETE OTP
    # --------------------------------

    OtpStore.delete_otp(
        chat_id
    )

    return jsonify({

        "success": True
    })

# --------------------------------
# PROTECTED API
# --------------------------------

@app.route(

    "/secure_data",

    methods=["POST"]
)
def secure_data():

    auth = (

        AuthMiddleware
        .verify_request()
    )

    if auth:
        return auth

    return jsonify({

        "success": True,

        "message":
            "Secure endpoint accessed",

        "user_id":
            g.user_id,

        "device_id":
            g.device_id,

        "session_id":
            g.session_id
    })

# --------------------------------
# REFRESH TOKEN
# --------------------------------

@app.route(

    "/refresh_token",

    methods=["POST"]
)
def refresh_token():

    refresh_token = request.json.get(
        "refresh_token"
    )

    if not refresh_token:

        return jsonify({

            "success": False,

            "message":
                "Missing refresh token"

        }), 400

    refreshed = (

        RefreshHandler
        .refresh_access_token(
            refresh_token
        )
    )

    if not refreshed["success"]:

        return jsonify(
            refreshed
        ), 401

    return jsonify(
        refreshed
    )

# --------------------------------
# HEALTH CHECK
# --------------------------------

@app.route("/")
def home():

    return jsonify({

        "success": True,

        "message":
            "NetBridge Secure Backend Running"
    })

# --------------------------------
# START SERVER
# --------------------------------

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=10000
    )
