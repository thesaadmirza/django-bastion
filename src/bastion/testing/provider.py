"""A configurable stand-in for an OpenID Provider.

Presets encode what each vendor actually emits, taken from their own
documentation rather than from what the spec says they should emit. The
differences are not cosmetic: a rule written against Okta's group names will
never match Entra's group GUIDs, and Google does not put groups in an ID token
at all.
"""

from __future__ import annotations

import datetime as dt
import secrets
from dataclasses import dataclass, field
from typing import Any, Literal

from bastion.testing import tokens
from bastion.testing.keys import SigningKey, generate_key

Vendor = Literal["generic", "entra", "okta", "google", "keycloak"]

# Fixed so that exp/iat assertions are reproducible. Tests that care about
# expiry pass an explicit `now`.
DEFAULT_NOW = dt.datetime(2026, 7, 28, 12, 0, 0, tzinfo=dt.UTC)


@dataclass
class FakeIdP:
    issuer: str = "https://idp.example.test"
    client_id: str = "bastion-test-client"
    vendor: Vendor = "generic"
    keys: list[SigningKey] = field(default_factory=list)
    now: dt.datetime = DEFAULT_NOW

    #: Overrides applied to the discovery document. A value of ``None`` removes
    #: the key, which is how a provider that omits an optional field is
    #: modelled. Real providers do this: Entra publishes no
    #: ``code_challenge_methods_supported`` at all.
    discovery_overrides: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.keys:
            self.keys = [generate_key()]

    # ----------------------------------------------------------------- keys --

    @property
    def active_key(self) -> SigningKey:
        """Newest key. Rotation appends, so the tail is current."""
        return self.keys[-1]

    def rotate_key(self, *, retire_old: bool = False) -> SigningKey:
        """Add a new signing key.

        By default the old key stays published, which is what real providers
        do during a rollover window. Entra documents a 24-hour overlap. Pass
        ``retire_old=True`` to model the case where an RP cached a key that has
        since disappeared.
        """
        new = generate_key()
        if retire_old:
            self.keys = [new]
        else:
            self.keys.append(new)
        return new

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        return {"keys": [k.public_jwk() for k in self.keys]}

    # ------------------------------------------------------------ discovery --

    def discovery_document(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/authorize",
            "token_endpoint": f"{self.issuer}/token",
            "userinfo_endpoint": f"{self.issuer}/userinfo",
            "jwks_uri": f"{self.issuer}/.well-known/jwks.json",
            "end_session_endpoint": f"{self.issuer}/logout",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
            "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "name"],
            "authorization_response_iss_parameter_supported": True,
        }
        if self.vendor == "entra":
            doc["subject_types_supported"] = ["pairwise"]
            # Verified against the live document: Entra's v2.0 metadata has no
            # code_challenge_methods_supported field, though it accepts S256.
            doc.pop("code_challenge_methods_supported", None)

        for key, value in self.discovery_overrides.items():
            if value is None:
                doc.pop(key, None)
            else:
                doc[key] = value
        if self.vendor == "google":
            # Verified against the live document: Google publishes no
            # end_session_endpoint, so RP-initiated logout is impossible.
            doc.pop("end_session_endpoint")
            doc["claims_supported"] = [
                "aud",
                "email",
                "email_verified",
                "exp",
                "family_name",
                "given_name",
                "iat",
                "iss",
                "name",
                "picture",
                "sub",
            ]
        return doc

    # --------------------------------------------------------------- claims --

    def base_claims(
        self,
        *,
        subject: str = "user-0001",
        nonce: str | None = "test-nonce",
        lifetime: int = 300,
        **overrides: Any,
    ) -> dict[str, Any]:
        iat = int(self.now.timestamp())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": subject,
            "aud": self.client_id,
            "iat": iat,
            "exp": iat + lifetime,
            "auth_time": iat,
            "name": "Test Person",
            "email": "test.person@example.test",
        }
        if nonce is not None:
            claims["nonce"] = nonce

        if self.vendor == "entra":
            # sub is pairwise per application; oid is the tenant-stable id and
            # the only safe join key. email_verified is not emitted at all.
            claims["oid"] = f"oid-{subject}"
            claims["tid"] = "tenant-0001"
            claims["sub"] = f"pairwise-{secrets.token_hex(4)}-{subject}"
            claims["preferred_username"] = claims["email"]
        elif self.vendor == "google":
            claims["email_verified"] = True
            claims["hd"] = "example.test"
        elif self.vendor == "okta":
            claims["email_verified"] = True

        claims.update(overrides)
        return claims

    # ---------------------------------------------------------------- tokens --

    def id_token(self, *, key: SigningKey | None = None, **claim_overrides: Any) -> str:
        key = key or self.active_key
        header = {"alg": key.alg, "typ": "JWT", "kid": key.kid}
        return tokens.sign(header, self.base_claims(**claim_overrides), key)

    def id_token_with(self, claims: dict[str, Any], *, key: SigningKey | None = None) -> str:
        """Mint from a fully-specified claim set, bypassing the defaults."""
        key = key or self.active_key
        header = {"alg": key.alg, "typ": "JWT", "kid": key.kid}
        return tokens.sign(header, claims, key)

    def access_token(self) -> str:
        return secrets.token_urlsafe(32)

    def at_hash(self, access_token: str) -> str:
        return tokens.left_half_hash(access_token, self.active_key.alg)

    # ---------------------------------------------------------------- groups --

    def with_groups(self, names: list[str], **claim_overrides: Any) -> dict[str, Any]:
        """Group claim in the shape this vendor actually emits.

        Entra sends object GUIDs unless the tenant opts in to names. Keycloak
        sends full paths when the mapper's path toggle is on. Google sends
        nothing at all, which is why the key is absent rather than empty.
        """
        claims = self.base_claims(**claim_overrides)
        if self.vendor == "entra":
            claims["groups"] = [f"00000000-0000-0000-0000-{i:012d}" for i, _ in enumerate(names)]
        elif self.vendor == "keycloak":
            claims["groups"] = [f"/{n}" for n in names]
        elif self.vendor == "google":
            pass  # no group claim exists in Google's ID token
        else:
            claims["groups"] = list(names)
        return claims

    def with_group_overage(self, *, count: int = 200, **claim_overrides: Any) -> dict[str, Any]:
        """Entra's overage response.

        Above 150 groups for SAML or 200 for a JWT, Entra drops the groups
        claim and substitutes a pointer to Microsoft Graph. An RP that treats
        the missing claim as "this user has no groups" silently strips every
        group-derived permission. An RP that treats it as "grant nothing and
        carry on" is safe; one that fails open is not.
        """
        claims = self.base_claims(**claim_overrides)
        claims.pop("groups", None)
        claims["_claim_names"] = {"groups": "src1"}
        claims["_claim_sources"] = {
            "src1": {
                "endpoint": (
                    f"https://graph.microsoft.com/v1.0/users/"
                    f"{claims.get('oid', claims['sub'])}/getMemberObjects"
                )
            }
        }
        claims["hasgroups"] = True
        self.overage_group_count = count
        return claims


def entra(**kwargs: Any) -> FakeIdP:
    kwargs.setdefault("issuer", "https://login.microsoftonline.com/tenant-0001/v2.0")
    return FakeIdP(vendor="entra", **kwargs)


def okta(**kwargs: Any) -> FakeIdP:
    kwargs.setdefault("issuer", "https://example.okta.com/oauth2/default")
    return FakeIdP(vendor="okta", **kwargs)


def google(**kwargs: Any) -> FakeIdP:
    kwargs.setdefault("issuer", "https://accounts.google.com")
    return FakeIdP(vendor="google", **kwargs)


def keycloak(**kwargs: Any) -> FakeIdP:
    kwargs.setdefault("issuer", "https://kc.example.test/realms/test")
    return FakeIdP(vendor="keycloak", **kwargs)
