from __future__ import annotations

import unittest
from types import SimpleNamespace

from services.register.openai_register import _is_cloudflare_challenge


def response(status_code: int, headers: dict[str, str], text: str = ""):
    return SimpleNamespace(status_code=status_code, headers=headers, text=text)


class CloudflareDetectionTests(unittest.TestCase):
    def test_cloudflare_server_header_alone_is_not_a_challenge(self) -> None:
        resp = response(
            200,
            {"Server": "cloudflare", "Content-Type": "application/json"},
            '{"ok": true}',
        )

        self.assertFalse(_is_cloudflare_challenge(resp))

    def test_cf_mitigated_challenge_header_is_a_challenge(self) -> None:
        resp = response(
            403,
            {
                "Server": "cloudflare",
                "Cf-Mitigated": "challenge",
                "Content-Type": "text/html",
            },
            "",
        )

        self.assertTrue(_is_cloudflare_challenge(resp))

    def test_cloudflare_challenge_page_is_a_challenge(self) -> None:
        resp = response(
            403,
            {"Server": "cloudflare", "Content-Type": "text/html"},
            '<html><head><title>Just a moment...</title></head>'
            '<body><script src="https://challenges.cloudflare.com/turnstile/v0/api.js">'
            "</script></body></html>",
        )

        self.assertTrue(_is_cloudflare_challenge(resp))


if __name__ == "__main__":
    unittest.main()
