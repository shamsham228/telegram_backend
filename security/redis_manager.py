import redis
import os

class RedisManager:

    _client = None

    @classmethod
    def get_client(cls):

        if cls._client is None:

            cls._client = redis.Redis(

                host=os.getenv(
                    "REDIS_HOST",
                    "localhost"
                ),

                port=int(
                    os.getenv(
                        "REDIS_PORT",
                        6379
                    )
                ),

                password=os.getenv(
                    "REDIS_PASSWORD",
                    None
                ),

                decode_responses=True
            )

        return cls._client
