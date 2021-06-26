import jwt
from tanner.config import TannerConfig


def generate():
    key = TannerConfig.get("API", "auth_signature")
    encoded = jwt.encode({"user": "tanner_owner"}, key, algorithm="HS256")
    return encoded.decode("utf-8")
