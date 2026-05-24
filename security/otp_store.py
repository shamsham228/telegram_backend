import os
import json
import redis

REDIS_HOST = os.getenv(
    "REDIS_HOST"
)

REDIS_PORT = int(
    os.getenv(
        "REDIS_PORT",
        6379
    )
)

REDIS_PASSWORD = os.getenv(
    "REDIS_PASSWORD"
)

redis_client = redis.Redis(

    host=REDIS_HOST,

    port=REDIS_PORT,

    password=REDIS_PASSWORD,

    decode_responses=True,

    ssl=True
)

class OtpStore:

    @staticmethod
    def save_otp(

        chat_id,

        otp,

        expiry_seconds=35
    ):

        payload = {

            "otp": otp
        }

        redis_client.setex(

            f"otp:{chat_id}",

            expiry_seconds,

            json.dumps(payload)
        )

    @staticmethod
    def get_otp(chat_id):

        data = redis_client.get(
            f"otp:{chat_id}"
        )

        if not data:
            return None

        return json.loads(data)

    @staticmethod
    def delete_otp(chat_id):

        redis_client.delete(
            f"otp:{chat_id}"
        )
