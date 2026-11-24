"""Authentication and role checks for Plan B Studio (interface stub, task P0-S3).

Purpose: decorators that routes use to require a logged-in user and a minimum
role on the event named in the URL.
Important logic (to be implemented in P1-S3 and P1-S4):
  * Tokens are PyJWT HS256 with a 30-minute expiry; passwords use Argon2id.
  * require_auth sets g.user_id from the token, or answers 401.
  * require_role looks up the caller's membership role for the event in the
    URL and sets g.role. Not a member -> 404; role too low -> 403.
  * Membership roles are ordered viewer < lead < editor < organiser.
  * role_to_pool turns a membership role into the database role name that
    get_conn() should use.
Until implemented, the stubs raise NotImplementedError when a decorated
route is CALLED, so importing this module never breaks the app.
"""
from functools import wraps

# Membership roles from lowest to highest rights.
ROLE_ORDER = ("viewer", "lead", "editor", "organiser")


def require_auth(view):
    """Decorator: check the bearer token, set g.user_id, else return 401."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        raise NotImplementedError("P1-S3")

    return wrapper


def require_role(min_role):
    """Decorator factory: require at least min_role on the event in the URL.

    min_role: one of ROLE_ORDER. Sets g.role for the view. Answers 404 if the
    caller is not a member of the event and 403 if their role is too low.
    """

    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            raise NotImplementedError("P1-S4")

        return wrapper

    return decorator


def role_to_pool(role):
    """Map a membership role to the database role name for get_conn().

    role: one of ROLE_ORDER. Returns 'viewer', 'lead', 'editor' or 'organiser'.
    """
    raise NotImplementedError("P1-S4")
