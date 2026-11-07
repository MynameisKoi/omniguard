"""Brand inference (#4): which brand a login page presents itself as.

The old detector returned the first keyword hit anywhere on the page, so most
real login pages came back as "Google Workspace" (their "Continue with Google"
button) and Amazon as "Okta" ("single sign-on"). These pin the cases down.
"""

import os
import sys

import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
verifyeye_dir = os.path.join(repo_root, "verifyeye-ingress")
if verifyeye_dir not in sys.path:
    sys.path.insert(0, verifyeye_dir)

from visual.detector import infer_brand_from_page  # noqa: E402

OAUTH = "Continue with Google  Continue with Apple  Sign in with Microsoft"


@pytest.mark.parametrize("title, url, actions, text, expected", [
    # real login pages: their own brand, despite third-party sign-in buttons
    ("Sign in to GitHub · GitHub", "https://github.com/login", ["/session"], OAUTH, "GitHub"),
    ("Log in | TikTok", "https://www.tiktok.com/login", [], "Use QR code " + OAUTH, "TikTok"),
    ("Netflix", "https://www.netflix.com/login", [], "Enter your info to sign in", "Netflix"),
    ("Sign in", "https://www.amazon.com/ap/signin", ["https://www.amazon.com/ap/signin"],
     "Sign in or create account. Single sign-on (SSO) for business", "Amazon"),
    ("Log in | Notion", "https://www.notion.so/login", [], OAUTH, "Notion"),
    ("Sign in - Google Accounts", "https://accounts.google.com/", [], "Use your Google Account", "Google"),
    ("Sign in to your account", "https://login.microsoftonline.com/", [], "Sign in", "Microsoft"),
    ("Just a moment...", "https://claude.ai/login", [], "Verify you are human", "Claude"),
    # phishing kits: no real domain, but the title / form target give them away
    ("Netflix Sign In", "http://localhost:5800/", ["https://netflix-account-verify.com/collect"], "", "Netflix"),
    ("Claude", "http://localhost:5500/", ["https://claude-login-verify.com/collect"], OAUTH, "Claude"),
    ("Sign in", "http://evil.example/", ["https://amazon-signin-verify.com/collect"], "Amazon", "Amazon"),
])
def test_names_the_page_s_own_brand(title, url, actions, text, expected):
    assert infer_brand_from_page(title=title, url=url, form_actions=actions, page_text=text) == expected


def test_oauth_buttons_alone_name_no_brand():
    # a generic login page whose only brand words are third-party buttons
    assert infer_brand_from_page("Log in", "https://example.com/login", [], OAUTH) is None


def test_generic_phrases_name_no_brand():
    # these used to mean Microsoft / Okta / Amazon / Facebook
    text = "Sign in to your account. Single sign-on (SSO). Prime metadata."
    assert infer_brand_from_page("Sign in", "https://example.com/", [], text) is None


def test_whole_words_only():
    # "meta" inside "metadata", "chase" inside "purchase"
    assert infer_brand_from_page("Purchase", "https://shop.example/", [], "metadata purchase") is None


def test_a_passing_mention_is_not_enough():
    # one mention in body text scores 1, below the threshold
    assert infer_brand_from_page("Welcome", "https://example.com/", [], "We also support PayPal.") is None
