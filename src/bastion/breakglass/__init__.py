"""Emergency access.

The fire escape. When the identity provider is unreachable, every account in a
correctly configured deployment is unreachable with it, including the ones that
would fix the problem. This is the way back in.

It exists for two independent reasons, which is unusual and worth stating
because it changes how seriously to take it.

The obvious one is availability: a provider outage should not be an outage of
your ability to respond to the outage.

The less obvious one came out of the accessibility work. WCAG's conformance
requirement covers every page in a process, and the provider's own login page
is part of the login process. A deployment where the provider is the *only* way
in inherits that page's conformance, whatever it happens to be, with no
recourse. A locally controlled path means our own process has a conforming
route end to end regardless. So break-glass is an accessibility control as well
as a security one, and shipping without it would have been a conformance
problem rather than only a resilience one.

Design comes from Microsoft's emergency-access account guidance, AWS root-user
practice, and HashiCorp Vault's root tokens, which agree on more than they
disagree: at least two accounts, credentials that do not expire and are not
subject to automated cleanup, authentication that does not depend on the system
being bypassed, and alerting loud enough that use is never quiet.

The last of those is the one this module refuses to make optional. A
break-glass account nobody is told about is a backdoor with paperwork.
"""

from bastion.breakglass.models import BreakGlassAccount
from bastion.breakglass.service import (
    BreakGlassDenied,
    authenticate_break_glass,
    is_break_glass,
)

__all__ = [
    "BreakGlassAccount",
    "BreakGlassDenied",
    "authenticate_break_glass",
    "is_break_glass",
]
