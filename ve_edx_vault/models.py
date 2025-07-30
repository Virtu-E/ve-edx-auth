from typing import TypedDict


class EdxUserDetails(TypedDict):
    """TypedDict for EdX user details passed between services."""
    username: str
    user_id: int
    full_name: str
    email: str
    first_name: str
    last_name: str


class TokenResponse(TypedDict):
    """TypedDict for authentication token response from edu vault."""
    expiry: str  # ISO format datetime string
    token: str   # Authentication token
