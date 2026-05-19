from flask import Flask, request, jsonify
import requests
import random
import time
import threading
import os

app = Flask(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")

BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# -----------------------------
# SAVED USERS
# -----------------------------

users = {}

# -----------------------------
# ACTIVE OTPS
# -----------------------------

otp_store = {}

# -----------------------------
# TELEGRAM WEBHOOK
# -----------------------------

@app.route("/telegram", methods=["POST"])
def telegram_webhook():

    data = request.json

    if "message" not in data:
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

    # -----------------------------
    # /START
    # -----------------------------

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

                    "Welcome to NetBridge\n\n"
                    "Press button below to share your phone number.",

                "reply_markup": {

                    "keyboard": [

                        [
                            {
                                "text": "Share Phone Number",
                                "request_contact": True
                            }
                        ]
                    ],

                    "resize_keyboard": True,

                    "one_time_keyboard": True
                }
            }
        )

    # -----------------------------
    # SAVE PHONE NUMBER
    # -----------------------------

    if "contact" in message:

        phone = message["contact"]["phone_number"]

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

# -----------------------------
# SEND OTP
# -----------------------------

@app.route("/send_otp", methods=["POST"])
def send_otp():

    data = request.json

    identifier = data.get(
        "identifier",
        ""
    ).replace("@", "").lower()

    matched_user = None

    for user in users.values():

        saved_username = user.get(
            "username",
            ""
        ).lower()

        saved_phone = user.get(
            "phone",
            ""
        ).replace("+", "")

        clean_identifier = identifier.replace(
            "+",
            ""
        )

        if (

            saved_username == clean_identifier

            or

            saved_phone == clean_identifier
        ):

            matched_user = user

            break

    if matched_user is None:

        return jsonify({

            "success": False,

            "message":
                "User not found. Open bot and press /start first."
        })

    chat_id = matched_user["chat_id"]

    # -----------------------------
    # GENERATE OTP
    # -----------------------------

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

    # -----------------------------
    # SEND OTP MESSAGE
    # -----------------------------

    response = requests.post(

        f"{BASE_URL}/sendMessage",

        json={

            "chat_id": chat_id,

            "text":

                f"🔐 NetBridge OTP\n\n"
                f"Code: {otp}\n\n"
                f"Expires in 35 seconds."
        }
    ).json()

    # -----------------------------
    # GET MESSAGE ID
    # -----------------------------

    message_id = response["result"]["message_id"]

    # -----------------------------
    # AUTO DELETE OTP
    # -----------------------------

    def delete_message():

        time.sleep(35)

        try:

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
        target=delete_message
    ).start()

    return jsonify({

        "success": True
    })

# -----------------------------
# VERIFY OTP
# -----------------------------

@app.route("/verify_otp", methods=["POST"])
def verify_otp():

    data = request.json

    identifier = data.get(
        "identifier",
        ""
    ).replace("@", "").lower()

    otp = data.get(
        "otp",
        ""
    )

    matched_user = None

    for user in users.values():

        saved_username = user.get(
            "username",
            ""
        ).lower()

        saved_phone = user.get(
            "phone",
            ""
        ).replace("+", "")

        clean_identifier = identifier.replace(
            "+",
            ""
        )

        if (

            saved_username == clean_identifier

            or

            saved_phone == clean_identifier
        ):

            matched_user = user

            break

    if matched_user is None:

        return jsonify({

            "success": False,

            "message": "User not found"
        })

    chat_id = matched_user["chat_id"]

    if chat_id not in otp_store:

        return jsonify({

            "success": False,

            "message": "OTP expired"
        })

    saved = otp_store[chat_id]

    # -----------------------------
    # EXPIRED
    # -----------------------------

    if int(time.time()) > saved["expiry"]:

        del otp_store[chat_id]

        return jsonify({

            "success": False,

            "message": "OTP expired"
        })

    # -----------------------------
    # INVALID OTP
    # -----------------------------

    if saved["otp"] != otp:

        return jsonify({

            "success": False,

            "message": "Invalid OTP"
        })

    # -----------------------------
    # SUCCESS
    # -----------------------------

    del otp_store[chat_id]

    return jsonify({

        "success": True
    })

# -----------------------------
# HOME
# -----------------------------

@app.route("/")
def home():

    return "Telegram OTP Backend Running"

# -----------------------------
# START
# -----------------------------

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=10000
    )
