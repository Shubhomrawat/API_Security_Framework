"""
core/auth.py — Auth flow manager: Bearer, API Key, OAuth2 client-credentials
"""
from __future__ import annotations
import os
import time
import httpx
from dataclasses import dataclass, field
from core.logger import get_logger

logger = get_logger("auth")


@dataclass
class AuthToken:
    header_name: str
    header_value: str
    expires_at: float = 0.0          # epoch seconds; 0 = never expires

    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False
        return time.time() >= self.expires_at - 30   # 30-second buffer

    def as_header(self) -> dict[str, str]:
        return {self.header_name: self.header_value}


class AuthManager:
    """
    Manages authentication tokens and refreshes them transparently.

    Supported modes
    ───────────────
    bearer      Static Bearer token — e.g. --auth "Bearer eyJ…"
    apikey      API key header — e.g. --auth-mode apikey --apikey-name X-Api-Key
    oauth2      OAuth2 client-credentials flow (auto-refreshes on expiry)
    none        No auth
    """

    def __init__(
        self,
        mode: str = "none",
        # bearer / apikey
        static_header_name: str = "Authorization",
        static_header_value: str = "",
        # oauth2
        token_url: str = "",
        client_id: str = "",
        client_secret: str = "",
        scope: str = "",
        # apikey override name
        apikey_header: str = "X-Api-Key",
    ):
        self.mode = mode.lower()
        self.static_header_name = static_header_name
        self.static_header_value = static_header_value
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.apikey_header = apikey_header

        self._cached: AuthToken | None = None

    # ── Public API ────────────────────────────────────────────────────────────

    def get_headers(self) -> dict[str, str]:
        """Return auth headers, refreshing if necessary."""
        if self.mode == "none":
            return {}

        if self.mode in ("bearer", "apikey"):
            return self._static_headers()

        if self.mode == "oauth2":
            return self._oauth2_headers()

        logger.warning(f"Unknown auth mode '{self.mode}', using none")
        return {}

    # ── Modes ─────────────────────────────────────────────────────────────────

    def _static_headers(self) -> dict[str, str]:
        if not self.static_header_value:
            return {}
        name = self.static_header_name
        if self.mode == "apikey":
            name = self.apikey_header
        return {name: self.static_header_value}

    def _oauth2_headers(self) -> dict[str, str]:
        if self._cached and not self._cached.is_expired():
            return self._cached.as_header()

        logger.info("[AuthManager] Fetching OAuth2 access token …")
        try:
            resp = httpx.post(
                self.token_url,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": self.scope,
                },
                timeout=15.0,
            )
            resp.raise_for_status()
            data = resp.json()
            token = data["access_token"]
            expires_in = int(data.get("expires_in", 3600))
            self._cached = AuthToken(
                header_name="Authorization",
                header_value=f"Bearer {token}",
                expires_at=time.time() + expires_in,
            )
            logger.info(f"[AuthManager] OAuth2 token acquired (expires in {expires_in}s)")
            return self._cached.as_header()
        except Exception as exc:
            logger.error(f"[AuthManager] OAuth2 token fetch failed: {exc}")
            return {}

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> "AuthManager":
        """Build an AuthManager from environment variables."""
        mode = os.getenv("AUTH_MODE", "none")
        return cls(
            mode=mode,
            static_header_name=os.getenv("AUTH_HEADER_NAME", "Authorization"),
            static_header_value=os.getenv("AUTH_HEADER_VALUE", ""),
            token_url=os.getenv("OAUTH2_TOKEN_URL", ""),
            client_id=os.getenv("OAUTH2_CLIENT_ID", ""),
            client_secret=os.getenv("OAUTH2_CLIENT_SECRET", ""),
            scope=os.getenv("OAUTH2_SCOPE", ""),
            apikey_header=os.getenv("APIKEY_HEADER_NAME", "X-Api-Key"),
        )

    @classmethod
    def from_bearer(cls, token: str) -> "AuthManager":
        value = token if token.startswith("Bearer ") else f"Bearer {token}"
        return cls(mode="bearer", static_header_value=value)
