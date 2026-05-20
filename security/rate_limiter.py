import time

from security.redis_manager import (
    RedisManager
)


class RateLimiter:

    # --------------------------------
    # GENERIC LIMITER
    # --------------------------------

    @staticmethod
    def is_allowed(

        key: str,

        limit: int,

        window_seconds: int
    ) -> bool:

        client = (
            RedisManager
            .get_client()
        )

        current = client.get(key)

        # --------------------------------
        # FIRST REQUEST
        # --------------------------------

        if current is None:

            client.setex(

                key,

                window_seconds,

                1
            )

            return True

        count = int(current)

        # --------------------------------
        # LIMIT EXCEEDED
        # --------------------------------

        if count >= limit:

            return False

        # --------------------------------
        # INCREMENT
        # --------------------------------

        client.incr(key)

        return True

    # --------------------------------
    # OTP SEND LIMIT
    # --------------------------------

    @staticmethod
    def allow_otp_send(

        identifier: str,

        ip: str
    ) -> bool:

        user_key = (

            f"otp_send_user:"
            f"{identifier}"
        )

        ip_key = (

            f"otp_send_ip:"
            f"{ip}"
        )

        user_allowed = (

            RateLimiter
            .is_allowed(

                user_key,

                limit=5,

                window_seconds=600
            )
        )

        ip_allowed = (

            RateLimiter
            .is_allowed(

                ip_key,

                limit=20,

                window_seconds=600
            )
        )

        return (

            user_allowed and
            ip_allowed
        )

    # --------------------------------
    # OTP VERIFY LIMIT
    # --------------------------------

    @staticmethod
    def allow_otp_verify(

        identifier: str,

        ip: str
    ) -> bool:

        user_key = (

            f"otp_verify_user:"
            f"{identifier}"
        )

        ip_key = (

            f"otp_verify_ip:"
            f"{ip}"
        )

        user_allowed = (

            RateLimiter
            .is_allowed(

                user_key,

                limit=10,

                window_seconds=600
            )
        )

        ip_allowed = (

            RateLimiter
            .is_allowed(

                ip_key,

                limit=30,

                window_seconds=600
            )
        )

        return (

            user_allowed and
            ip_allowed
        )

    # --------------------------------
    # REFRESH TOKEN LIMIT
    # --------------------------------

    @staticmethod
    def allow_refresh(

        user_id: str
    ) -> bool:

        key = (

            f"refresh_token:"
            f"{user_id}"
        )

        return (

            RateLimiter
            .is_allowed(

                key,

                limit=50,

                window_seconds=3600
            )
        )

    # --------------------------------
    # LOGIN LIMIT
    # --------------------------------

    @staticmethod
    def allow_login(

        ip: str
    ) -> bool:

        key = (

            f"login:"
            f"{ip}"
        )

        return (

            RateLimiter
            .is_allowed(

                key,

                limit=20,

                window_seconds=900
            )
        )

    # --------------------------------
    # API REQUEST LIMIT
    # --------------------------------

    @staticmethod
    def allow_api_request(

        user_id: str
    ) -> bool:

        key = (

            f"api_request:"
            f"{user_id}"
        )

        return (

            RateLimiter
            .is_allowed(

                key,

                limit=300,

                window_seconds=60
            )
        )
