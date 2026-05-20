import time

from security.jwt_manager import (
    JwtManager
)

from security.token_store import (
    TokenStore
)

class RefreshHandler:

    # --------------------------------
    # REFRESH ACCESS TOKEN
    # --------------------------------

    @staticmethod
    def refresh_access_token(

        refresh_token
    ):

        # --------------------------------
        # REVOKED TOKEN
        # --------------------------------

        if (

            TokenStore
            .is_revoked(
                refresh_token
            )
        ):

            return {

                "success": False,

                "message":
                    "Refresh token revoked"
            }

        # --------------------------------
        # VERIFY TOKEN
        # --------------------------------

        verified = (

            JwtManager
            .verify_token(
                refresh_token
            )
        )

        if not verified["success"]:

            return verified

        payload = verified[
            "payload"
        ]

        # --------------------------------
        # TOKEN TYPE
        # --------------------------------

        if (

            payload.get("type")
            != "refresh"

        ):

            return {

                "success": False,

                "message":
                    "Invalid refresh token"
            }

        user_id = payload.get(
            "user_id"
        )

        device_id = payload.get(
            "device_id"
        )

        # --------------------------------
        # ACTIVE TOKEN CHECK
        # --------------------------------

        active_refresh = (

            TokenStore
            .get_refresh_token(
                user_id
            )
        )

        if active_refresh != refresh_token:

            return {

                "success": False,

                "message":
                    "Refresh token mismatch"
            }

        # --------------------------------
        # CREATE NEW ACCESS TOKEN
        # --------------------------------

        new_access = (

            JwtManager
            .create_access_token(

                user_id,

                device_id
            )
        )

        access_expiry = (

            int(time.time()) + 900
        )

        # --------------------------------
        # ROTATE ACCESS TOKEN
        # --------------------------------

        TokenStore.rotate_access_token(

            user_id,

            new_access,

            access_expiry
        )

        # --------------------------------
        # CREATE NEW REFRESH TOKEN
        # --------------------------------

        new_refresh = (

            JwtManager
            .create_refresh_token(

                user_id,

                device_id
            )
        )

        refresh_expiry = (

            int(time.time()) + 604800
        )

        # --------------------------------
        # ROTATE REFRESH TOKEN
        # --------------------------------

        TokenStore.rotate_refresh_token(

            user_id,

            new_refresh,

            refresh_expiry
        )

        # --------------------------------
        # REVOKE OLD REFRESH
        # --------------------------------

        TokenStore.revoke_token(
            refresh_token
        )

        return {

            "success": True,

            "access_token":
                new_access,

            "refresh_token":
                new_refresh
        }
