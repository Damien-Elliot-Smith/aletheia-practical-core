"""
aletheia.spine.signing — External Integrity Anchor (Phase 1.1)

Closes RT-01: the hash chain is internally consistent but forgeable by anyone
with filesystem access and knowledge of SHA256. HMAC-SHA256 window signing
makes forging also require the signing key.

Design:
- sign_fn / verify_fn interface: opaque bytes in, opaque bytes out.
- Two built-in implementations: HMACSigner (recommended) and NullSigner (v1 compat).
- RFC3161Signer interface defined but not wired to a live TSA (Phase 3 territory).
- Key lives OUTSIDE the evidence root: environment variable or OS keystore.
- Backward compatible: if no signer is configured, Aletheia operates as v1.
  A missing HMAC on a signed deployment is FAIL, not INCONCLUSIVE.

signing_mode values (stored in sealed.json and case_manifest):
  NONE          — no signing, v1 behaviour
  HMAC_SHA256   — HMAC-SHA256 over window_root_hash with a secret key
  RFC3161       — timestamp authority token (interface defined, live TSA in Phase 3)
"""
from __future__ import annotations
import hashlib
import hmac
import os
from typing import Optional

SIGNING_MODE_NONE = "NONE"
SIGNING_MODE_HMAC = "HMAC_SHA256"
SIGNING_MODE_RFC3161 = "RFC3161"


class SigningError(Exception):
    pass


class VerificationError(Exception):
    pass


class NullSigner:
    """v1-compatible no-op signer. signing_mode = NONE."""
    signing_mode: str = SIGNING_MODE_NONE

    def sign(self, window_root_hash: str) -> Optional[bytes]:
        return None

    def verify(self, window_root_hash: str, signature: Optional[bytes]) -> bool:
        return True


class HMACSigner:
    """
    HMAC-SHA256 window signing.

    Key management:
      Pass key bytes directly or load from environment variable.
      Recommended: HMACSigner.from_env("ALETHEIA_HMAC_KEY")
      Key must NOT be stored on disk alongside the evidence.

    A missing signature on a deployment that expects HMAC_SHA256 is FAIL.
    HMAC comparison is constant-time to prevent timing attacks.
    """
    signing_mode: str = SIGNING_MODE_HMAC

    def __init__(self, key: bytes) -> None:
        if not key:
            raise SigningError("HMAC key must be non-empty bytes")
        self._key = key

    @classmethod
    def from_env(cls, env_var: str = "ALETHEIA_HMAC_KEY") -> "HMACSigner":
        val = os.environ.get(env_var)
        if not val:
            raise SigningError(
                f"HMAC key not found in environment variable '{env_var}'. "
                "Set this variable before running Aletheia. "
                "The key must live outside the evidence root directory."
            )
        return cls(key=val.encode("utf-8"))

    def sign(self, window_root_hash: str) -> bytes:
        h = hmac.new(self._key, window_root_hash.encode("utf-8"), hashlib.sha256)
        return h.digest()

    def verify(self, window_root_hash: str, signature: Optional[bytes]) -> bool:
        if signature is None:
            raise VerificationError(
                "seal_signature absent but signing_mode is HMAC_SHA256. "
                "This window was expected to be signed — treating as FAIL."
            )
        expected = hmac.new(self._key, window_root_hash.encode("utf-8"), hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)


class RFC3161Signer:
    """
    RFC 3161 Timestamp Authority interface (Phase 3 full implementation).
    Defined now so sealed.json can record signing_mode = RFC3161 today.
    Live TSA submission wired in Phase 3.
    """
    signing_mode: str = SIGNING_MODE_RFC3161

    def __init__(self, tsa_url: Optional[str] = None) -> None:
        self.tsa_url = tsa_url

    def sign(self, window_root_hash: str) -> Optional[bytes]:
        raise NotImplementedError(
            "RFC3161Signer requires a live TSA endpoint. Use HMACSigner for now."
        )

    def verify(self, window_root_hash: str, signature: Optional[bytes]) -> bool:
        raise NotImplementedError("RFC3161 verification requires Phase 3 implementation.")


def get_signer_from_env(env_var: str = "ALETHEIA_HMAC_KEY") -> "NullSigner | HMACSigner":
    """
    Convenience factory: HMACSigner if env var is set, NullSigner otherwise.
    Recommended entry point for production SpineLedger setup.
    """
    val = os.environ.get(env_var)
    if val:
        return HMACSigner(key=val.encode("utf-8"))
    return NullSigner()
