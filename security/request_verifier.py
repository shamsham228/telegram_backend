import hmac
import base64
import hashlib
import time

USED_NONCES = set()

MAX_REQUEST_AGE = 60


class RequestVerifier:

    @staticmethod
    def generate_secret(

        access_token: str,

        device_id: str
    ) -> str:

        combined = (
            f"{access_token}:{device_id}"
        )

        digest = hashlib.sha256(
            combined.encode()
        ).digest()

        return base64.b64encode(
            digest
        ).decode()

    @staticmethod
    def create_signature(

        payload: str,

        secret: str
    ) -> str:

        signature = hmac.new(

            secret.encode(),

            payload.encode(),

            hashlib.sha256

        ).digest()

        return base64.b64encode(
            signature
        ).decode()

    @staticmethod
    def verify_request(

        body: str,

        timestamp: str,

        nonce: str,

        device_id: str,

        access_token: str,

        received_signature: str
    ) -> bool:

        """
        REPLAY CHECK
        """

        if nonce in USED_NONCES:
            return False

        """
        TIMESTAMP CHECK
        """

        current_time = int(time.time())

        request_time = int(
            int(timestamp) / 1000
        )

        if abs(
            current_time - request_time
        ) > MAX_REQUEST_AGE:

            return False

        """
        STORE NONCE
        """

        USED_NONCES.add(
            nonce
        )

        """
        BUILD PAYLOAD
        """

        payload = (
            f"{body}|"
            f"{timestamp}|"
            f"{nonce}|"
            f"{device_id}"
        )

        """
        SECRET
        """

        secret = (
            RequestVerifier
            .generate_secret(

                access_token,

                device_id
            )
        )

        """
        EXPECTED SIGNATURE
        """

        expected = (
            RequestVerifier
            .create_signature(

                payload,

                secret
            )
        )

        return hmac.compare_digest(

            expected,

            received_signature
        )
