from flask import Flask, request, jsonify
import requests
import random
import time
import threading
import os
from security.request_verifier import RequestVerifier

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")

BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# --------------------------------
# SECURITY STORAGE
# --------------------------------

USED_NONCES = set()

FAILED_REQUESTS = {}

ACTIVE_SESSIONS = {}

MAX_FAILS = 10

MAX_REQUEST_AGE = 60

# --------------------------------
# USERS
# --------------------------------

users = {}

# --------------------------------
# OTP STORE
# --------------------------------

otp_store = {}

# --------------------------------
# FRAUD DETECTION
# --------------------------------

def record_failure(ip):

    FAILED_REQUESTS[ip] = (

        FAILED_REQUESTS.get(
            ip,
            0
        ) + 1
    )

def is_blocked(ip):

    return FAILED_REQUESTS.get(
        ip,
        0
    ) >= MAX_FAILS

# --------------------------------
# SESSION STORE
# --------------------------------

def register_session(

    user_id,

    session_id
):

    ACTIVE_SESSIONS[
        user_id
    ] = session_id

def validate_session(

    user_id,

    session_id
):

    return ACTIVE_SESSIONS.get(
        user_id
    ) == session_id

def revoke_session(

    user_id
):

    if user_id in ACTIVE_SESSIONS:

        del ACTIVE_SESSIONS[
            user_id
        ]

# --------------------------------
# SECURE REQUEST VERIFICATION
# --------------------------------

def verify_secure_request():

    ip = request.remote_addr

    # -----------------------------
    # BLOCKED IP
    # -----------------------------

    if is_blocked(ip):

        return jsonify({

            "success": False,

            "message":
                "Too many failed requests"

        }), 429

    # -----------------------------
    # HEADERS
    # -----------------------------

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

    # -----------------------------
    # EMPTY CHECK
    # -----------------------------

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

    # -----------------------------
    # BODY
    # -----------------------------

    body = request.get_data(
        as_text=True
    )

    # -----------------------------
    # VERIFY SIGNATURE
    # -----------------------------

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

    # -----------------------------
    # INVALID REQUEST
    # -----------------------------

    if not valid:

        record_failure(ip)

        return jsonify({

            "success": False,

            "message":
                "Invalid secure request"

        }), 403

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

    if not data or "message" not in data:

        return "ok"

    message = data["message"]

    chat_id = message["chat"]["id"]

    username = message["from"].get(
        "username",
        ""
    ).lower()

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

            "chat_id": chat_id,

            "username": username,

            "first_name": first_name,

            "phone": ""
        }

        requests.post(

            f"{BASE_URL}/sendMessage",

            json={

                "chat_id": chat_id,

                "text":

                    f"Connected Successfully\n\n"
                    f"Username: @{username}\n"
                    f"Id: {chat_id}\n"
                    f"First: {first_name}\n\n"
                    f"Press button below to share your phone number.",

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
    # CONTACT SAVE
    # --------------------------------

    if "contact" in message:

        phone = message["contact"][
            "phone_number"
        ]

        if chat_id in users:

            users[chat_id]["phone"] = phone

        requests.post(

            f"{BASE_URL}/sendMessage",

            json={

                "chat_id": chat_id,

                "text":

                    "Phone number saved successfully.\n\n"
                    "You can now login inside NetBridge."
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

        saved_username = user.get(
            "username",
            ""
        ).lower()

        saved_phone = user.get(
            "phone",
            ""
        ).replace("+", "")

        if (

            saved_username == clean_identifier

            or

            saved_phone == clean_identifier
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

    if matched_user is None:

        return jsonify({

            "success": False,

            "message":
                "User not found. Open bot and press /start first."
        })

    chat_id = matched_user["chat_id"]

    # --------------------------------
    # OTP
    # --------------------------------

    otp = str(

        random.randint(
            100000,
            999999
        )
    )

    expiry = int(time.time()) + 35

    otp_store[chat_id] = {

        "otp": otp,

        "expiry": expiry
    }

    # --------------------------------
    # SEND MESSAGE
    # --------------------------------

    response = requests.post(

        f"{BASE_URL}/sendMessage",

        json={

            "chat_id": chat_id,

            "text":

                f"🔐 NetBridge OTP Verification\n\n"
                f"OTP Code: {otp}\n\n"
                f"Expires in 35 seconds.\n"
                f"Do not share this code."
        }
    ).json()

    message_id = response.get(
        "result",
        {}
    ).get(
        "message_id"
    )

    # --------------------------------
    # AUTO DELETE
    # --------------------------------

    def delete_message():

        time.sleep(35)

        try:

            if message_id:

                requests.post(

                    f"{BASE_URL}/deleteMessage",

                    json={

                        "chat_id": chat_id,

                        "message_id": message_id
                    }
                )

        except:
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

    if chat_id not in otp_store:

        return jsonify({

            "success": False,

            "message":
                "OTP expired"
        })

    saved = otp_store[
        chat_id
    ]

    # --------------------------------
    # EXPIRED
    # --------------------------------

    if int(time.time()) > saved["expiry"]:

        del otp_store[chat_id]

        return jsonify({

            "success": False,

            "message":
                "OTP expired"
        })

    # --------------------------------
    # INVALID
    # --------------------------------

    if saved["otp"] != otp:

        return jsonify({

            "success": False,

            "message":
                "Invalid OTP"
        })

    # --------------------------------
    # SUCCESS
    # --------------------------------

    del otp_store[chat_id]

    return jsonify({

        "success": True
    })

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
