"""Typed errors.

Two rules about these.

They are typed so the pipeline can tell an infrastructure failure from a
credential failure and log the difference. They are **not** rendered to end
users. Everything that reaches a browser goes through a three-tier error
policy: a pre-authentication failure produces one generic body and one status
code regardless of which subclass was raised.
Anything else is an account-enumeration oracle.

None of these carry the token, the assertion, or the claim set. An exception
that ends up in a log aggregator should not hand a bearer credential to
whoever can read it.
"""

from __future__ import annotations


class BastionError(Exception):
    """Base for everything this package raises."""


class ConfigurationError(BastionError):
    """The deployment is wrong. Raised at startup wherever possible, so that
    ``manage.py check --deploy`` catches it rather than a user at 3am."""


class IncompleteConfiguration(ConfigurationError):
    """A required value is absent rather than wrong.

    The distinction is the difference between a state every deployment passes
    through and a mistake. A checkout whose ``BASTION_CLIENT_SECRET`` is not in
    the environment yet is incomplete; a connection naming a provider that does
    not exist is wrong, and stays wrong in every environment. The startup check
    warns about the first and refuses the second, so a developer checkout and a
    CI run boot and say why instead of having to write their settings
    conditionally to get past the check.

    Still a ``ConfigurationError``, because every existing caller catches that
    and must keep treating this as one: an incomplete connection cannot be used
    to sign anybody in, and ``bastion_doctor`` still fails on it.
    """


# --------------------------------------------------------------------------- #
# Token verification
# --------------------------------------------------------------------------- #


class TokenError(BastionError):
    """A token was rejected. Never distinguish these to the caller."""


class MalformedToken(TokenError):
    """Not a well-formed compact serialisation."""


class TokenTooLarge(TokenError):
    """Exceeds the configured byte cap, checked before any parsing.

    Guards the JOSE denial-of-service class: authlib CVE-2025-61920 and the
    ``zip: DEF`` decompression bomb CVE-2025-62706 both start with a token
    nobody bounded.
    """


class AlgorithmNotAllowed(TokenError):
    """The header's ``alg`` is not in the allowlist.

    Catches ``none`` and the whole HMAC family without either needing a special
    case, which is the point of expressing the policy as an allowlist rather
    than a denylist.
    """


class UntrustedKeyMaterial(TokenError):
    """The header tried to supply its own key via ``jwk``, ``jku``, ``x5u`` or
    ``x5c``.

    authlib CVE-2026-27962, rated critical: a token carrying its own key
    verifies against itself. The only defence is refusing to read key material
    from the message.
    """


class UnsupportedCriticalHeader(TokenError):
    """``crit`` names an extension we do not implement.

    RFC 7515 says reject. A library that ignores ``crit`` accepts a token whose
    semantics it does not understand (authlib CVE-2025-59420).
    """


class SignatureVerificationFailed(TokenError):
    """The signature did not verify against the resolved key."""


class KeyNotFound(TokenError):
    """No key matched the ``kid``.

    Deliberately an exception rather than a ``None`` return. Every fail-open
    bug in this space looks like a resolver that returned nothing and a caller
    that read nothing as "no signature required".
    """


# --------------------------------------------------------------------------- #
# Claim validation
# --------------------------------------------------------------------------- #


class ClaimValidationError(TokenError):
    """A claim failed validation. Subclasses exist for logging, not for
    branching in a view."""


class IssuerMismatch(ClaimValidationError):
    """``iss`` is not an exact string match for the configured issuer."""


class AudienceMismatch(ClaimValidationError):
    """``aud`` does not contain our client id, or contains an untrusted extra
    audience without a matching ``azp``."""


class TokenExpired(ClaimValidationError):
    pass


class TokenNotYetValid(ClaimValidationError):
    pass


class NonceMismatch(ClaimValidationError):
    """The nonce does not match the one bound to this browser transaction."""


class SubjectMismatch(ClaimValidationError):
    """UserInfo returned a different ``sub`` than the ID token.

    OIDC Core 5.3.2 makes discarding the response a MUST here.
    """


class AccessTokenHashMismatch(ClaimValidationError):
    """``at_hash`` did not match the access token we were handed."""


# --------------------------------------------------------------------------- #
# Discovery and key material
# --------------------------------------------------------------------------- #


class TransactionError(BastionError):
    """The browser transaction could not be resumed.

    Callers must not distinguish these to the user either. "Unknown state" and
    "already used" tell an attacker probing a stolen state value which of the
    two they are holding.
    """


class TransactionNotFound(TransactionError):
    """No record matches the returned ``state``."""


class TransactionExpired(TransactionError):
    """The record existed but its window has closed."""


class TransactionReplayed(TransactionError):
    """The record was consumed by someone else first.

    Single-use is what stops an authorization code being replayed into a
    second session.
    """


class ProvisioningConflict(BastionError):
    """A new identity resolved to a username that already exists locally.

    Raised rather than resolved, because every way of resolving it is worse.
    Adopting the existing account would mean letting a provider-supplied name
    select a local user, which is the account-takeover shape behind allauth
    CVE-2025-65431 and the reason ``IDENTITY.KEY`` is ``(issuer, subject)``.
    Renaming the incoming user to something free hands somebody an account
    under a name they did not choose and nobody can predict.

    The ordinary cause is benign: a site with existing Django accounts putting
    its admin behind SSO, where the first person to sign in already has a local
    login. It also appears when an issuer URL changes, since the identity is
    keyed on it, and when a second connection serves people who already signed
    in through the first.

    An operator resolves it by renaming one, by linking the two by hand, or by
    turning on ``IDENTITY["LINKING_POLICY"] = "verified_email_once"``, which
    adopts a local account on a *verified address from a pinned domain* rather
    than on a name the provider chose. That is the narrow case where adoption
    is defensible, and it is opt-in for the same reason this exception exists.
    """


class DiscoveryError(BastionError):
    """The provider's metadata could not be fetched or is unusable."""


class InsecureEndpoint(ConfigurationError):
    """An endpoint URL used a scheme we refuse.

    PyJWT's ``PyJWKClient`` accepted arbitrary schemes and turned a JWKS URI
    into an SSRF primitive and a local-file read (CVE-2026-48522).
    """


class KeyFetchThrottled(BastionError):
    """A key refetch was suppressed by the rate limiter.

    An attacker who can post tokens carrying arbitrary ``kid`` values must not
    be able to drive unbounded outbound requests (CVE-2026-48524).
    """
