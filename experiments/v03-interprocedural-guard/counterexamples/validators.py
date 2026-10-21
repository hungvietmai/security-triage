"""Validators used by the interprocedural-guard counterexamples (CWE-22).

Each function is written from the semantics it is meant to illustrate; the comments state what
a normal return guarantees about which value. No benchmark or project code is copied.
"""

import os
import pathlib
import uuid
from os.path import abspath, dirname, join, normcase, sep
from urllib.parse import unquote


def check_relative(path):
    """Normal return => `path` itself is relative, has no '..' component and no backslash."""
    if os.path.isabs(path) or ".." in path.split("/") or "\\" in path:
        raise ValueError("invalid path")
    return path


def check_relative_stripped(path):
    """Checks a transformed copy (query part removed) and returns that copy.

    Normal return => the RETURNED value is safe; the argument may still contain '..' after '?'.
    """
    path = path.split("?", 1)[0]
    if os.path.isabs(path) or ".." in path.split("/") or "\\" in path:
        raise ValueError("invalid path")
    return path


def check_contained(base, candidate):
    """Normal return => the canonical form of `candidate` lies under the canonical `base`."""
    real_base = pathlib.Path(base).resolve()
    real = pathlib.Path(candidate).resolve()
    if not real.is_relative_to(real_base):
        raise ValueError("outside base")
    return candidate


def safe_join_like(base, name):
    """Lexical containment; normal return => the RETURNED absolute path lies under `base`."""
    final = os.path.abspath(os.path.join(base, name))
    base_abs = os.path.abspath(base)
    if not final.startswith(base_abs + os.sep) and final != base_abs:
        raise ValueError("outside base")
    return final


def safe_join_three(base, name):
    """Containment with the three normal-return branches of Django's safe_join (semantics only).

    Normal return => the RETURNED absolute path starts with base + sep, OR equals base, OR base is
    the filesystem root (dirname(base) == base), where every absolute path passes.
    """
    final = os.path.normcase(os.path.abspath(os.path.join(base, name)))
    base_abs = os.path.normcase(os.path.abspath(base))
    if (
        not final.startswith(base_abs + os.sep)
        and final != base_abs
        and os.path.dirname(base_abs) != base_abs
    ):
        raise ValueError("outside base")
    return final


def safe_join_normcase(base, name):
    """The same three branches, with normcase applied inside each test (Django's layout).

    Normal return => the RETURNED absolute path starts with base + sep, OR equals base, OR base is
    the filesystem root. (Single `name` argument: with `*paths` the default query loses the flow.)
    """
    final = abspath(join(base, name))
    base_path = abspath(base)
    if (
        not normcase(final).startswith(normcase(base_path + sep))
        and normcase(final) != normcase(base_path)
        and dirname(normcase(base_path)) != normcase(base_path)
    ):
        raise ValueError("outside base")
    return final


def check_uuid(value):
    """Normal return => `value` parses as a UUID (hex digits, '-', braces, 'urn:uuid:' prefix)."""
    try:
        uuid.UUID(value)
    except (ValueError, TypeError) as e:
        raise ValueError("invalid id") from e


def check_nested(path):
    """Delegates to check_relative on the same, unmodified parameter."""
    check_relative(path)


def check_swallow(path):
    """Catches the validator's exception: returns normally for invalid input."""
    try:
        check_relative(path)
    except ValueError:
        print("invalid path ignored")


def check_no_dotdot(path):
    """Rejects '..' components only; absolute paths pass."""
    if ".." in path.split("/"):
        raise ValueError("invalid path")


def check_not_absolute(path):
    """Rejects absolute paths only; '..' passes."""
    if os.path.isabs(path):
        raise ValueError("invalid path")


def check_conditional(path, strict=False):
    """Raises only in strict mode."""
    if strict and (os.path.isabs(path) or ".." in path.split("/")):
        raise ValueError("invalid path")


def is_safe(path):
    """Boolean validator: never raises."""
    return not (os.path.isabs(path) or ".." in path.split("/") or "\\" in path)


def decode(value):
    """A transformation that can introduce '..' and '/' after a check."""
    return unquote(value)


def check_prefix_weak(base, candidate):
    """Flawed containment: startswith WITHOUT a trailing separator, plus an equality branch.

    Normal return => final == base, OR final starts with `base` (no separator) -- so a sibling
    directory sharing the prefix (e.g. '<base>-evil/...') passes. Returns the joined absolute path.
    """
    final = os.path.abspath(os.path.join(base, candidate))
    base_abs = os.path.abspath(base)
    if not final.startswith(base_abs) and final != base_abs:
        raise ValueError("outside base")
    return final


def check_contained_other(candidate):
    """Proves containment under a DIFFERENT root (PUBLIC), not the root the sink requires.

    Normal return => canonical `candidate` lies under PUBLIC_ROOT. Says nothing about DATA_ROOT.
    """
    public = pathlib.Path(PUBLIC_ROOT).resolve()
    real = pathlib.Path(candidate).resolve()
    if not real.is_relative_to(public):
        raise ValueError("outside public")
    return candidate


def prepend_parent(value):
    """A validator-shaped function that RETURNS a transformed, unsafe value."""
    return "../" + value


# ---- check shapes added after the development-set diagnostics (recognition gaps) ----


def check_relative_pure(path):
    """Normal return => `path` itself is relative (POSIX path flavour) and has no '..' component."""
    if pathlib.PurePosixPath(path).is_absolute() or ".." in path.split("/"):
        raise ValueError("invalid path")
    return path


def check_windows_absolute(path):
    """Uses the Windows path flavour: on POSIX, '/etc/passwd' is not absolute for it and passes."""
    if pathlib.PureWindowsPath(path).is_absolute() or ".." in path.split("/"):
        raise ValueError("invalid path")


def check_relative_decoded(path):
    """Decodes and may strip a 'file:' prefix (a conditional reassignment), then checks.

    Normal return => the RETURNED value does not start with '/' and has no '..' component.
    """
    path = unquote(path)
    if path.startswith("file:"):
        path = path[len("file:") :]
    if path.startswith("/") or ".." in path.split("/"):
        raise ValueError("invalid path")
    return path


class Checks:
    @staticmethod
    def relative(path):
        """Static-method form: normal return => `path` is relative and has no '..' component."""
        if os.path.isabs(path) or ".." in path.split("/"):
            raise ValueError("invalid path")


class Checker:
    def relative(self, path):
        """Instance-method form of the same check."""
        if os.path.isabs(path) or ".." in path.split("/"):
            raise ValueError("invalid path")


class LaxChecker(Checker):
    def relative(self, path):
        """An override that checks nothing."""


def pick_checker(lax):
    """Either checker; a call through the result has two possible targets."""
    return LaxChecker() if lax else Checker()


PUBLIC_ROOT = "/srv/public"
