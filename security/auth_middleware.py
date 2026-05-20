from flask import (
    request,
    jsonify,
    g
)

from security.jwt_manager import (
    JwtManager
)

from security.token_store import (
    TokenStore
)

from security.session_store import (
    validate_session
)

class AuthMiddleware:

    # --------------------------------
    # VERIFY AUTH
    # --------------------------------

    @staticmethod
    def verify_request():

        # --------------------------------
        # AUTH HEADER
        # --------------------------------

        auth_header = request.headers.get(
            "Authorization"
        )

        if (

            not auth_header or
            not auth_header.startswith(
                "Bearer "
            )

        ):

            return jsonify({

                "success": False,

                "message":
                    "Missing access token"

            }), 401

        # --------------------------------
        # EXTRACT TOKEN
        # --------------------------------

        token = (

            auth_header
            .replace(
                "Bearer ",
                ""
            )
            .strip()
        )

        # --------------------------------
        # REVOKED TOKEN
        # --------------------------------

        if (

            TokenStore
            .is_revoked(token)

        ):

            return jsonify({

                "success": False,

                "message":
                    "Revoked token"

            }), 401

        # --------------------------------
        # VERIFY JWT
        # --------------------------------

        verified = (

            JwtManager
            .verify_token(token)
        )

        if not verified["success"]:

            return jsonify({

                "success": False,

                "message":
                    verified["message"]

            }), 401

        payload = verified[
            "payload"
        ]

        # --------------------------------
        # TOKEN TYPE
        # --------------------------------

        if (

            payload.get("type")
            != "access"

        ):

            return jsonify({

                "success": False,

                "message":
                    "Invalid token type"

            }), 401

        # --------------------------------
        # USER
        # --------------------------------

        user_id = payload.get(
            "user_id"
        )

        # --------------------------------
        # DEVICE
        # --------------------------------

        token_device = payload.get(
            "device_id"
        )

        request_device = request.headers.get(
            "X-Device-ID"
        )

        if (

            not request_device or
            request_device != token_device

        ):

            return jsonify({

                "success": False,

                "message":
                    "Device mismatch"

            }), 403

        # --------------------------------
        # ACTIVE TOKEN CHECK
        # --------------------------------

        active_token = (

            TokenStore
            .get_access_token(
                user_id
            )
        )

        if active_token != token:

            return jsonify({

                "success": False,

                "message":
                    "Session expired"

            }), 401

        # --------------------------------
        # SESSION VALIDATION
        # --------------------------------

        session_id = request.headers.get(
            "X-Session-ID"
        )

        if (

            not session_id or

            not validate_session(

                user_id,

                session_id
            )
        ):

            return jsonify({

                "success": False,

                "message":
                    "Invalid session"

            }), 401

        # --------------------------------
        # SAVE USER CONTEXT
        # --------------------------------

        g.user_id = user_id

        g.device_id = token_device

        g.session_id = session_id

        return None
