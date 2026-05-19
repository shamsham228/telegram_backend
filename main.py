from flask import Flask, request, jsonify
from telegram import Bot
from dotenv import load_dotenv
import os
import random
import time

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
BOT_USERNAME = os.getenv("BOT_USERNAME")

bot = Bot(token=BOT_TOKEN)

app = Flask(__name__)

# Temporary OTP storage
otp_store = {}

OTP_EXPIRY = 35  # seconds


@app.route("/")
def home():

    return "NetBridge Telegram OTP Backend Running"


"""
Request OTP
"""
@app.route("/request_otp", methods=["POST"])
def request_otp():

    data = request.json

    telegram_id = data.get("telegram_id")

    if not telegram_id:

        return jsonify({
            "success": False,
            "message": "telegram_id missing"
        }), 400

    otp = str(
        random.randint(100000, 999999)
    )

    expiry = time.time() + OTP_EXPIRY

    otp_store[str(telegram_id)] = {
        "otp": otp,
        "expiry": expiry,
        "used": False
    }

    try:

        bot.send_message(

            chat_id=telegram_id,

            text=
            f"🔐 NetBridge OTP\n\n"
            f"Your OTP: {otp}\n\n"
            f"Expires in 35 seconds."
        )

        return jsonify({
            "success": True,
            "message": "OTP sent"
        })

    except Exception as e:

        return jsonify({
            "success": False,
            "message": str(e)
        }), 500


"""
Verify OTP
"""
@app.route("/verify_otp", methods=["POST"])
def verify_otp():

    data = request.json

    telegram_id = str(
        data.get("telegram_id")
    )

    otp = data.get("otp")

    if telegram_id not in otp_store:

        return jsonify({
            "success": False,
            "message": "OTP not found"
        }), 400

    stored = otp_store[telegram_id]

    if stored["used"]:

        return jsonify({
            "success": False,
            "message": "OTP already used"
        }), 400

    if time.time() > stored["expiry"]:

        return jsonify({
            "success": False,
            "message": "OTP expired"
        }), 400

    if stored["otp"] != otp:

        return jsonify({
            "success": False,
            "message": "Invalid OTP"
        }), 400

    stored["used"] = True

    return jsonify({
        "success": True,
        "message": "Login successful"
    })


"""
Get Telegram User ID
"""
@app.route("/telegram_id", methods=["POST"])
def telegram_id():

    data = request.json

    updates = bot.get_updates()

    for update in updates:

        if update.message:

            username = update.message.from_user.username

            if username == data.get("username"):

                return jsonify({
                    "success": True,
                    "telegram_id":
                    update.message.chat_id
                })

    return jsonify({
        "success": False,
        "message": "User not found. Start bot first."
    })


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=10000
    )