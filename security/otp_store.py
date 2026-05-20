import json

from security.redis_manager import (
    RedisManager
)

class OtpStore:

    PREFIX = "otp:"

    @staticmethod
    def save_otp(

        chat_id,

        otp,

        expiry_seconds
    ):

        client = (
            RedisManager
            .get_client()
        )

        key = (
            f"{OtpStore.PREFIX}"
            f"{chat_id}"
        )

        value = json.dumps({

            "otp": otp
        })

        client.setex(

            key,

            expiry_seconds,

            value
        )

    @staticmethod
    def get_otp(chat_id):

        client = (
            RedisManager
            .get_client()
        )

        key = (
            f"{OtpStore.PREFIX}"
            f"{chat_id}"
        )

        data = client.get(key)

        if not data:

            return None

        return json.loads(data)

    @staticmethod
    def delete_otp(chat_id):

        client = (
            RedisManager
            .get_client()
        )

        key = (
            f"{OtpStore.PREFIX}"
            f"{chat_id}"
        )

        client.delete(key)
