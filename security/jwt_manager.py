import jwt
import time
import secrets

JWT_SECRET = (
    "NETBRIDGE_ULTRA_SECURE_SECRET"
)

JWT_ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRY = 900
# 15 minutes

REFRESH_TOKEN_EXPIRY = 604800
# 7 days

class JwtManager:

    # --------------------------------
    # CREATE ACCESS TOKEN
    # --------------------------------

    @staticmethod
    def create_access_token(

        user_id,

        device_id
    ):

        current = int(time.time())

        payload = {

            "user_id":
                user_id,

            "device_id":
                device_id,

            "type":
                "access",

            "iat":
                current,

            "exp":
                current +
                ACCESS_TOKEN_EXPIRY
        }

        token = jwt.encode(

            payload,

            JWT_SECRET,

            algorithm=
                JWT_ALGORITHM
        )

        return token

    # --------------------------------
    # CREATE REFRESH TOKEN
    # --------------------------------

    @staticmethod
    def create_refresh_token(

        user_id,

        device_id
    ):

        current = int(time.time())

        payload = {

            "user_id":
                user_id,

            "device_id":
                device_id,

            "type":
                "refresh",

            "nonce":
                secrets.token_hex(16),

            "iat":
                current,

            "exp":
                current +
                REFRESH_TOKEN_EXPIRY
        }

        token = jwt.encode(

            payload,

            JWT_SECRET,

            algorithm=
                JWT_ALGORITHM
        )

        return token

    # --------------------------------
    # VERIFY TOKEN
    # --------------------------------

    @staticmethod
    def verify_token(token):

        try:

            payload = jwt.decode(

                token,

                JWT_SECRET,

                algorithms=[
                    JWT_ALGORITHM
                ]
            )

            return {

                "success": True,

                "payload": payload
            }

        except jwt.ExpiredSignatureError:

            return {

                "success": False,

                "message":
                    "Token expired"
            }

        except jwt.InvalidTokenError:

            return {

                "success": False,

                "message":
                    "Invalid token"
            }

    # --------------------------------
    # EXTRACT USER
    # --------------------------------

    @staticmethod
    def get_user_id(token):

        verified = (

            JwtManager
            .verify_token(token)
        )

        if not verified["success"]:

            return None

        return verified[
            "payload"
        ].get(
            "user_id"
        )

    # --------------------------------
    # EXTRACT DEVICE
    # --------------------------------

    @staticmethod
    def get_device_id(token):

        verified = (

            JwtManager
            .verify_token(token)
        )

        if not verified["success"]:

            return None

        return verified[
            "payload"
        ].get(
            "device_id"
        )

    # --------------------------------
    # TOKEN TYPE
    # --------------------------------

    @staticmethod
    def get_token_type(token):

        verified = (

            JwtManager
            .verify_token(token)
        )

        if not verified["success"]:

            return None

        return verified[
            "payload"
        ].get(
            "type"
        )
