import time

ACTIVE_ACCESS_TOKENS = {}

ACTIVE_REFRESH_TOKENS = {}

REVOKED_TOKENS = set()

class TokenStore:

    # --------------------------------
    # SAVE ACCESS TOKEN
    # --------------------------------

    @staticmethod
    def save_access_token(

        user_id,

        token,

        expiry
    ):

        ACTIVE_ACCESS_TOKENS[
            user_id
        ] = {

            "token":
                token,

            "expiry":
                expiry
        }

    # --------------------------------
    # GET ACCESS TOKEN
    # --------------------------------

    @staticmethod
    def get_access_token(

        user_id
    ):

        saved = (

            ACTIVE_ACCESS_TOKENS
            .get(user_id)
        )

        if not saved:

            return None

        # EXPIRED

        if (

            int(time.time())
            > saved["expiry"]

        ):

            del ACTIVE_ACCESS_TOKENS[
                user_id
            ]

            return None

        return saved["token"]

    # --------------------------------
    # SAVE REFRESH TOKEN
    # --------------------------------

    @staticmethod
    def save_refresh_token(

        user_id,

        token,

        expiry
    ):

        ACTIVE_REFRESH_TOKENS[
            user_id
        ] = {

            "token":
                token,

            "expiry":
                expiry
        }

    # --------------------------------
    # GET REFRESH TOKEN
    # --------------------------------

    @staticmethod
    def get_refresh_token(

        user_id
    ):

        saved = (

            ACTIVE_REFRESH_TOKENS
            .get(user_id)
        )

        if not saved:

            return None

        # EXPIRED

        if (

            int(time.time())
            > saved["expiry"]

        ):

            del ACTIVE_REFRESH_TOKENS[
                user_id
            ]

            return None

        return saved["token"]

    # --------------------------------
    # REVOKE TOKEN
    # --------------------------------

    @staticmethod
    def revoke_token(token):

        REVOKED_TOKENS.add(
            token
        )

    # --------------------------------
    # TOKEN REVOKED?
    # --------------------------------

    @staticmethod
    def is_revoked(token):

        return token in (
            REVOKED_TOKENS
        )

    # --------------------------------
    # REMOVE USER TOKENS
    # --------------------------------

    @staticmethod
    def clear_user_tokens(

        user_id
    ):

        if (

            user_id in
            ACTIVE_ACCESS_TOKENS

        ):

            del ACTIVE_ACCESS_TOKENS[
                user_id
            ]

        if (

            user_id in
            ACTIVE_REFRESH_TOKENS

        ):

            del ACTIVE_REFRESH_TOKENS[
                user_id
            ]

    # --------------------------------
    # ROTATE ACCESS TOKEN
    # --------------------------------

    @staticmethod
    def rotate_access_token(

        user_id,

        new_token,

        expiry
    ):

        old = (

            ACTIVE_ACCESS_TOKENS
            .get(user_id)
        )

        if old:

            REVOKED_TOKENS.add(
                old["token"]
            )

        ACTIVE_ACCESS_TOKENS[
            user_id
        ] = {

            "token":
                new_token,

            "expiry":
                expiry
        }

    # --------------------------------
    # ROTATE REFRESH TOKEN
    # --------------------------------

    @staticmethod
    def rotate_refresh_token(

        user_id,

        new_token,

        expiry
    ):

        old = (

            ACTIVE_REFRESH_TOKENS
            .get(user_id)
        )

        if old:

            REVOKED_TOKENS.add(
                old["token"]
            )

        ACTIVE_REFRESH_TOKENS[
            user_id
        ] = {

            "token":
                new_token,

            "expiry":
                expiry
        }
