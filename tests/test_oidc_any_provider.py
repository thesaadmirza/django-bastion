"""Providers nobody wrote a class for.

Five profiles ship. There are far more than five identity providers, and the
ones that are missing are missing in the same way every time: the claims are
all there, under names this package has never heard of.

Each case below is a token shaped the way that vendor's own documentation says
it arrives, run through the configured generic profile. They are shapes from
documentation rather than captures from live tenants, which is the same
standard the `okta` and `keycloak` profiles are held to and is recorded as such
in the provider matrix.
"""

from __future__ import annotations

from typing import Any

import pytest

from bastion.claims import GroupFormat, Verified
from bastion.exceptions import ClaimValidationError, ConfigurationError
from bastion.protocols.oidc.quirks import (
    REGISTRY,
    GenericQuirks,
    ProviderQuirks,
    resolve,
    to_identity_claims,
)

ISSUER = "https://idp.example.test"


def identity(claims: dict[str, Any], **kwargs: Any) -> Any:
    return to_identity_claims(claims, quirks=GenericQuirks(**kwargs), issuer=ISSUER)


class TestProvidersWithNoProfile:
    """One case per vendor, configured the way its documentation describes."""

    def test_auth0_with_a_namespaced_group_claim(self) -> None:
        """Auth0 requires custom claims to be namespaced with a URI, so the
        group list never arrives under a name anybody would guess."""
        result = identity(
            {
                "sub": "auth0|653f1c",
                "email": "ada@example.com",
                "email_verified": True,
                "https://example.com/groups": ["django-staff", "django-admins"],
            },
            groups_claim="https://example.com/groups",
            groups_format="display_name",
        )
        assert result.subject == "auth0|653f1c"
        assert result.groups == ("django-staff", "django-admins")
        assert result.group_value_format is GroupFormat.DISPLAY_NAME
        assert result.may_escalate_privileges()

    def test_aws_cognito_prefixes_its_claims(self) -> None:
        result = identity(
            {
                "sub": "e4f8a1c2-0000-4a1b-9c3d-1122334455aa",
                "email": "ada@example.com",
                "email_verified": True,
                "cognito:groups": ["django-staff"],
                "cognito:username": "ada",
            },
            groups_claim="cognito:groups",
            groups_format="display_name",
        )
        assert result.groups == ("django-staff",)
        assert result.subject_source == "sub"

    def test_ping_identity_uses_memberof(self) -> None:
        result = identity(
            {"sub": "ada", "email": "ada@example.com", "memberOf": ["CN=Admins,OU=Groups"]},
            groups_claim="memberOf",
            groups_format="qualified",
        )
        assert result.groups == ("CN=Admins,OU=Groups",)
        assert result.group_value_format is GroupFormat.QUALIFIED_NAME

    def test_zitadel_roles_under_a_urn(self) -> None:
        result = identity(
            {
                "sub": "221",
                "email": "ada@example.com",
                "urn:zitadel:iam:org:project:roles": ["admin"],
            },
            groups_claim="urn:zitadel:iam:org:project:roles",
            groups_format="display_name",
        )
        assert result.groups == ("admin",)

    def test_authentik_is_already_spec_shaped(self) -> None:
        """Some providers need no configuration at all, which is worth pinning:
        the defaults have to keep working for the ones that are conformant."""
        result = identity(
            {
                "sub": "6f1a",
                "email": "ada@example.com",
                "email_verified": True,
                "groups": ["authentik Admins"],
            }
        )
        assert result.groups == ("authentik Admins",)
        assert result.email_verified is Verified.YES

    def test_a_provider_whose_subject_is_not_sub(self) -> None:
        """The Entra problem, met on a provider with no profile: `sub` is
        pairwise per client, and something else is the stable identifier."""
        result = identity(
            {"sub": "pairwise-per-client", "user_id": "stable-42", "email": "ada@example.com"},
            subject_claim="user_id",
        )
        assert result.subject == "stable-42"
        assert result.subject_source == "user_id"


class TestMultiTenantPinning:
    """The control that stops a provider serving somebody else's tenant."""

    def test_a_matching_tenant_passes(self) -> None:
        result = identity(
            {"sub": "ada", "org_id": "org_abc", "email": "ada@example.com"},
            expected_claims={"org_id": "org_abc"},
        )
        assert result.subject == "ada"

    def test_a_different_tenant_is_refused(self) -> None:
        """A perfectly valid token, signed by the right key, for the wrong
        organisation. Every other check passes."""
        with pytest.raises(ClaimValidationError, match="org_id"):
            identity(
                {"sub": "mallory", "org_id": "org_someone_else", "email": "m@evil.test"},
                expected_claims={"org_id": "org_abc"},
            )

    def test_an_absent_tenant_claim_is_refused(self) -> None:
        """Absent is not a match. A provider that stopped sending the claim
        must not silently stop enforcing the boundary."""
        with pytest.raises(ClaimValidationError, match="org_id"):
            identity({"sub": "ada", "email": "ada@example.com"}, expected_claims={"org_id": "x"})

    def test_several_claims_can_be_pinned(self) -> None:
        with pytest.raises(ClaimValidationError):
            identity(
                {"sub": "ada", "org_id": "org_abc", "env": "staging"},
                expected_claims={"org_id": "org_abc", "env": "production"},
            )


class TestEmailClaimMapping:
    def test_a_namespaced_email_claim(self) -> None:
        result = identity(
            {"sub": "ada", "https://example.com/mail": "ada@example.com"},
            email_claim="https://example.com/mail",
        )
        assert result.email == "ada@example.com"

    def test_a_separately_named_verified_flag(self) -> None:
        result = identity(
            {"sub": "ada", "email": "ada@example.com", "mail_confirmed": True},
            email_verified_claim="mail_confirmed",
        )
        assert result.email_verified is Verified.YES

    @pytest.mark.parametrize(
        ("sent", "expected"),
        [
            (True, Verified.YES),
            (False, Verified.NO),
            ("true", Verified.YES),
            ("false", Verified.NO),
            (None, Verified.UNKNOWN),
            ("yes", Verified.UNKNOWN),
            (1, Verified.UNKNOWN),
        ],
    )
    def test_verified_spellings(self, sent: Any, expected: Verified) -> None:
        """Some providers send the string rather than the boolean. Anything
        else is unknown rather than guessed, because this claim decides whether
        an address may adopt an existing administrator's account."""
        claims: dict[str, Any] = {"sub": "ada", "email": "ada@example.com"}
        if sent is not None:
            claims["email_verified"] = sent
        assert identity(claims).email_verified is expected

    def test_a_missing_email_is_none_not_an_error(self) -> None:
        """Plenty of providers can be configured to send no address at all."""
        assert identity({"sub": "ada"}).email is None

    def test_a_non_string_email_is_ignored(self) -> None:
        assert identity({"sub": "ada", "email": {"value": "x"}}).email is None


class TestRefusingBadConfiguration:
    """These are settings mistakes, and every one of them fails quiet.

    An empty groups claim reads every token as "member of nothing", which
    strips privileges and looks exactly like a provider problem.
    """

    @pytest.mark.parametrize("name", ["subject_claim", "groups_claim", "email_claim"])
    @pytest.mark.parametrize("value", ["", "   ", None, 7])
    def test_an_unusable_claim_name_is_refused(self, name: str, value: Any) -> None:
        with pytest.raises(ConfigurationError, match=name):
            GenericQuirks(**{name: value})

    def test_an_unknown_group_format_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="groups_format"):
            GenericQuirks(groups_format="guid")

    def test_the_error_lists_the_formats_that_exist(self) -> None:
        with pytest.raises(ConfigurationError, match="display_name"):
            GenericQuirks(groups_format="nope")

    def test_mfa_methods_can_be_replaced(self) -> None:
        """`amr` values are not standardised in practice. A provider that
        spells its second factor something this package has never seen would
        otherwise never satisfy require_mfa, whatever the person did.
        """
        quirks = GenericQuirks(mfa_methods=["pwd_plus_sms"])
        assert quirks.mfa_satisfied({"amr": ["pwd_plus_sms"]}) is True
        # And the defaults are replaced, not added to: a deployment that names
        # its methods is saying these are the ones that count.
        assert quirks.mfa_satisfied({"amr": ["otp"]}) is False
        assert GenericQuirks().mfa_satisfied({"amr": ["otp"]}) is True

    def test_an_empty_mfa_method_set_is_refused(self) -> None:
        """It would mean no assertion ever satisfies require_mfa, which reads
        as MFA being enforced while nobody can ever pass it."""
        with pytest.raises(ConfigurationError, match="mfa_methods"):
            GenericQuirks(mfa_methods=[])

    def test_a_missing_subject_claim_names_the_claim(self) -> None:
        with pytest.raises(ClaimValidationError, match="user_id"):
            identity({"sub": "ada"}, subject_claim="user_id")


class TestCustomProfileByImportPath:
    """For quirks no claim name can express."""

    def test_an_import_path_resolves(self) -> None:
        loaded = resolve("tests.test_oidc_any_provider.SplitSubjectQuirks")
        assert loaded is SplitSubjectQuirks

    def test_a_registry_name_still_wins(self) -> None:
        for name, cls in REGISTRY.items():
            assert resolve(name) is cls

    def test_a_custom_profile_does_what_it_says(self) -> None:
        result = to_identity_claims(
            {"tenant": "acme", "uid": "42", "email": "ada@example.com"},
            quirks=SplitSubjectQuirks(),
            issuer=ISSUER,
        )
        assert result.subject == "acme:42"
        assert result.subject_source == "tenant+uid"

    def test_an_unknown_bare_name_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="unknown provider"):
            resolve("nosuchprovider")

    def test_an_unimportable_path_is_refused(self) -> None:
        with pytest.raises(ConfigurationError, match="could not import"):
            resolve("tests.test_oidc_any_provider.NoSuchClass")

    def test_a_path_to_something_else_is_refused(self) -> None:
        """A typo pointing at an unrelated object fails at startup with the
        reason, rather than at the first login with an AttributeError."""
        with pytest.raises(ConfigurationError, match="not a ProviderQuirks"):
            resolve("tests.test_oidc_any_provider.ISSUER")


class SplitSubjectQuirks(ProviderQuirks):
    """A subject assembled from two claims, which no setting can express."""

    identifier = "split-subject"

    def subject(self, claims: Any) -> tuple[str, str]:
        tenant, uid = claims.get("tenant"), claims.get("uid")
        if not isinstance(tenant, str) or not isinstance(uid, str):
            raise ClaimValidationError("tenant and uid are both required")
        return f"{tenant}:{uid}", "tenant+uid"


class TestConfigurationFailsAtStartup:
    """`quirks_kwargs` is forwarded to a constructor, which makes it the
    opaque-dict shape the checks module opens by naming as the thing to avoid.

    An unforwarded name has to be a startup error. Lazily it would boot fine,
    pass every check, and raise a TypeError at somebody's first login.
    """

    def test_a_misspelled_option_is_refused_when_the_connection_is_built(self) -> None:
        from bastion.connections import build_connection

        with pytest.raises(ConfigurationError, match="group_claim"):
            build_connection(
                "corp",
                {
                    "issuer": ISSUER,
                    "client_id": "abc",
                    "provider": "generic",
                    "quirks_kwargs": {"group_claim": "roles"},
                },
            )

    def test_the_refusal_lists_what_the_profile_does_accept(self) -> None:
        """ "unexpected keyword argument" says what is wrong and not what would
        be right, and the answer is otherwise only in the source."""
        from bastion.connections import build_connection

        with pytest.raises(ConfigurationError, match="groups_claim, groups_format"):
            build_connection(
                "corp",
                {
                    "issuer": ISSUER,
                    "client_id": "abc",
                    "provider": "generic",
                    "quirks_kwargs": {"nope": 1},
                },
            )

    def test_a_bad_claim_name_is_refused_at_build_time_too(self) -> None:
        from bastion.connections import build_connection

        with pytest.raises(ConfigurationError, match="groups_claim"):
            build_connection(
                "corp",
                {
                    "issuer": ISSUER,
                    "client_id": "abc",
                    "provider": "generic",
                    "quirks_kwargs": {"groups_claim": ""},
                },
            )

    def test_the_profile_is_built_once(self) -> None:
        """It used to be rebuilt per access, which repeated the validation on
        every login and every doctor run for an object that never changes."""
        from bastion.connections import build_connection

        conn = build_connection(
            "corp", {"issuer": ISSUER, "client_id": "abc", "provider": "generic"}
        )
        assert conn.quirks is conn.quirks


class TestGroupCompleteness:
    def test_a_configured_provider_reports_its_groups_complete(self) -> None:
        """Only Entra and Keycloak can detect truncation. Everyone else says
        complete, which is the honest answer: no evidence of truncation is not
        the same as evidence there was none, but it is all the token offers."""
        result = identity({"sub": "ada", "groups": ["a"]})
        assert result.groups_complete is True
        assert result.may_escalate_privileges()

    def test_no_group_claim_at_all_is_empty_and_complete(self) -> None:
        result = identity({"sub": "ada"})
        assert result.groups == ()
        assert result.groups_complete is True

    def test_a_single_string_group_is_read_as_one_group(self) -> None:
        """Some providers send a bare string when there is exactly one."""
        assert identity({"sub": "ada", "groups": "solo"}).groups == ("solo",)

    def test_a_group_list_with_a_non_string_is_ignored_entirely(self) -> None:
        """Partially reading a malformed list would grant on half the evidence."""
        assert identity({"sub": "ada", "groups": ["ok", 7]}).groups == ()
