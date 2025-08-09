import os
import re
from typing import Dict, Any

# JWT Configuration
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is required")

JWT_CONFIG: Dict[str, Any] = {
    "algorithm": "HS256",
    "exp_minutes": int(os.getenv("JWT_EXP_MINUTES", "60")),
    "issuer": os.getenv("JWT_ISSUER", "social-media-api"),
    "required_claims": ["exp", "iat", "sub", "iss"]
}

# Password Configuration
PASSWORD_CONFIG: Dict[str, Any] = {
    "min_length": int(os.getenv("PASSWORD_MIN_LEN", "8")),
    "max_length": int(os.getenv("PASSWORD_MAX_LEN", "100")),
    "bcrypt_rounds": int(os.getenv("BCRYPT_ROUNDS", "12"))
}

# Username Configuration
USERNAME_CONFIG: Dict[str, Any] = {
    "min_length": 3,
    "max_length": 30,
    "regex": re.compile(r"^\w{3,30}$")
}

# Elasticsearch Configuration
ES_CONFIG: Dict[str, Any] = {
    "user_index": "users",
    "default_role": "user"
}

# HTTP Configuration
HTTP_CONFIG: Dict[str, Any] = {
    "default_headers": {
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
    },
    "error_content_type": "application/json; charset=utf-8"
}

# Error Messages
ERROR_MESSAGES: Dict[str, Any] = {
    "invalid_json": "Invalid JSON format",
    "validation_error": {
        "username": "Username must be 3-30 chars: letters, numbers, underscores only",
        "password": f"Password must be {PASSWORD_CONFIG['min_length']}-{PASSWORD_CONFIG['max_length']} characters",
        "credentials": "Username and password required"
    },
    "username_taken": "Username already taken",
    "invalid_credentials": "Invalid username or password",
    "missing_token": "Bearer token required",
    "invalid_token": "Invalid or expired token",
    "registration_failed": "Registration failed. Please try again.",
    "login_failed": "Login failed. Please try again."
}


# Add these to your existing configurations.py
USER_PROFILE_CONFIG = {
    "bio_max_length": int(os.getenv("BIO_MAX_LENGTH", "280")),
    "display_name_max_length": int(os.getenv("DISPLAY_NAME_MAX_LENGTH", "50")),
    "url_pattern": re.compile(
        r'^http?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\.?|'
        r'localhost|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/?|[/?]\S+)$',
        re.IGNORECASE
    )
}

PAGINATION_CONFIG = {
    "default_page": 1,
    "min_page_size": 1,
    "default_page_size": 20,
    "max_page_size": 100
}

USER_STATS_DEFAULTS = {
    "posts_count": 0,
    "followers_count": 0,
    "following_count": 0
}

USER_ROLES = ["user", "admin"]

ERROR_MESSAGES.update({
    "invalid_username": "Username cannot be empty",
    "user_not_found": "User not found",
    "fetch_error": "Could not retrieve user profile",
    "validation_error": {
        "display_name": f"display_name must be <= {USER_PROFILE_CONFIG['display_name_max_length']} characters",
        "bio": f"bio must be <= {USER_PROFILE_CONFIG['bio_max_length']} characters",
        "avatar_url": "avatar_url must be a valid URL",
        "email": "email must be a valid email address",
        "role": f"role must be one of: {', '.join(USER_ROLES)}"
    },
    "no_changes": "No valid fields to update",
    "update_error": "Could not update profile",
    "delete_error": "Could not deactivate account",
    "missing_query": "Search query is required",
    "query_too_short": "Query must be at least 2 characters",
    "search_error": "Could not perform user search",
    "forbidden": "Admin only"
})