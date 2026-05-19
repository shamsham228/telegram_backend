from flask import Flask, request, jsonify
import requests
import random
import time
import threading

app = Flask(__name__)

BOT_TOKEN = "YOUR_BOT_TOKEN"

BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# saved telegram users
users = {}

# active OTPs
otp_store = {}

# -----------------------------
# TELEGRAM UPDATE WEBHOOK
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

    text = message.get("text", "")

    # SAVE USER AFTER /start
    if text == "/start":

        users[username] = {

            "chat_id": chat_id,

            "username": username,

            "first_name": first_name
        }

        requests.post(

            f"{BASE_URL}/sendMessage",

            json={

                "chat_id": chat_id,

                "text":

                    f"Connected Successfully\n\n"
                    f"@{username}\n"
                    f"ID: {chat_id}\n"
                    f"First: {first_name}"
            }
        )

    return "ok"

# -----------------------------
# SEND OTP
# -----------------------------

@app.route("/send_otp", methods=["POST"])
def send_otp():

    data = request.json

    username = data.get(
        "username",
        ""
    ).replace("@", "").lower()

    if username not in users:

        return jsonify({

            "success": False,

            "message":
                "User not found. Open bot and press /start first."
        })

    user = users[username]

    chat_id = user["chat_id"]

    otp = str(

        random.randint(
            100000,
            999999
        )
    )

    expiry = int(time.time()) + 35

    otp_store[username] = {

        "otp": otp,

        "expiry": expiry
    }

    message = requests.post(

        f"{BASE_URL}/sendMessage",

        json={

            "chat_id": chat_id,

            "text":

                f"🔐 NetBridge OTP\n\n"
                f"Code: {otp}\n\n"
                f"Expires in 35 seconds."
        }
    ).json()

    message_id = message["result"]["message_id"]

    # AUTO DELETE OTP
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

    username = data.get(
        "username",
        ""
    ).replace("@", "").lower()

    otp = data.get("otp", "")

    if username not in otp_store:

        return jsonify({

            "success": False,

            "message": "OTP expired"
        })

    saved = otp_store[username]

    if int(time.time()) > saved["expiry"]:

        del otp_store[username]

        return jsonify({

            "success": False,

            "message": "OTP expired"
        })

    if saved["otp"] != otp:

        return jsonify({

            "success": False,

            "message": "Invalid OTP"
        })

    del otp_store[username]

    return jsonify({

        "success": True
    })

# -----------------------------

@app.route("/")
def home():

    return "Telegram OTP Backend Running"

# -----------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )
