from security.redis_manager import (
    RedisManager
)

class NonceStore:

    PREFIX = "nonce:"

    NONCE_EXPIRY_SECONDS = 120

    # --------------------------------
    # SAVE NONCE
    # --------------------------------

    @staticmethod
    def save_nonce(

        nonce
    ):

        client = (
            RedisManager
            .get_client()
        )

        key = (
            f"{NonceStore.PREFIX}"
            f"{nonce}"
        )

        client.setex(

            key,

            NonceStore
            .NONCE_EXPIRY_SECONDS,

            "1"
        )

    # --------------------------------
    # NONCE EXISTS
    # --------------------------------

    @staticmethod
    def nonce_exists(

        nonce
    ):

        client = (
            RedisManager
            .get_client()
        )

        key = (
            f"{NonceStore.PREFIX}"
            f"{nonce}"
        )

        return client.exists(key)

    # --------------------------------
    # VALIDATE NONCE
    # --------------------------------

    @staticmethod
    def validate_nonce(

        nonce
    ):

        # --------------------------------
        # EMPTY NONCE
        # --------------------------------

        if not nonce:

            return False

        # --------------------------------
        # REPLAY DETECTED
        # --------------------------------

        if (

            NonceStore
            .nonce_exists(nonce)

        ):

            return False

        # --------------------------------
        # STORE NONCE
        # --------------------------------

        NonceStore.save_nonce(
            nonce
        )

        return True
