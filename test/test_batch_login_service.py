from __future__ import annotations

import copy
import threading
import unittest

from services import batch_login_service as batch_login_module
from services.batch_login_service import BatchLoginService, EmailOtpLoginClient


class FakeCookies:
    def __init__(self) -> None:
        self.items: list[tuple[str, str, str | None]] = []

    def set(self, name: str, value: str, domain: str | None = None) -> None:
        self.items.append((name, value, domain))


class FakeResponse:
    def __init__(self, status_code: int, url: str, data: dict | None = None, text: str = "") -> None:
        self.status_code = status_code
        self.url = url
        self._data = copy.deepcopy(data or {})
        self.text = text if text else ("{}" if data is not None else "")
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        return copy.deepcopy(self._data)


class FakeSession:
    def __init__(self) -> None:
        self.cookies = FakeCookies()
        self.calls: list[dict] = []
        self.closed = False

    def request(self, method: str, url: str, **kwargs):
        method = method.upper()
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if "/api/accounts/authorize" in url:
            return FakeResponse(200, f"{batch_login_module.auth_base}/log-in/password")
        if "/api/accounts/passwordless/send-otp" in url:
            return FakeResponse(
                200,
                f"{batch_login_module.auth_base}/email-verification",
                {
                    "continue_url": f"{batch_login_module.auth_base}/email-verification",
                    "page": {"type": "email_otp_verification"},
                },
            )
        if "/api/accounts/email-otp/validate" in url:
            return FakeResponse(
                200,
                f"{batch_login_module.platform_oauth_redirect_uri}?code=test-auth-code&state=test-state",
            )
        raise AssertionError(f"unexpected request: {method} {url}")

    def close(self) -> None:
        self.closed = True


class FakeRegisterService:
    def __init__(self, config: dict):
        self.config = copy.deepcopy(config)
        self.updates: list[dict] = []

    def get(self) -> dict:
        return copy.deepcopy(self.config)

    def update(self, updates: dict) -> dict:
        self.updates.append(copy.deepcopy(updates))
        self.config.update(copy.deepcopy(updates))
        if "proxy" in updates and isinstance(self.config.get("mail"), dict):
            self.config["mail"]["proxy"] = str(self.config.get("proxy") or "").strip()
        return self.get()


class BatchLoginServiceTests(unittest.TestCase):
    def with_register_service(self, fake: FakeRegisterService, callback):
        original = batch_login_module.register_service
        try:
            batch_login_module.register_service = fake
            return callback()
        finally:
            batch_login_module.register_service = original

    def test_email_otp_login_uses_passwordless_otp_without_password(self) -> None:
        fake_session = FakeSession()
        original_create_session = batch_login_module.create_session
        original_remember_latest_message = batch_login_module.mail_provider.remember_latest_message
        original_wait_for_code = batch_login_module.mail_provider.wait_for_code
        original_build_sentinel = batch_login_module.build_sentinel_token_tuple
        original_request_token = batch_login_module.request_platform_oauth_token

        try:
            batch_login_module.create_session = lambda _proxy="": fake_session
            batch_login_module.mail_provider.remember_latest_message = lambda *_args, **_kwargs: None
            batch_login_module.mail_provider.wait_for_code = lambda *_args, **_kwargs: "123456"
            batch_login_module.build_sentinel_token_tuple = lambda *_args, **_kwargs: ("sentinel-token", "sentinel-cookie")
            batch_login_module.request_platform_oauth_token = lambda _session, code, verifier: {
                "access_token": f"access:{code}",
                "refresh_token": f"refresh:{verifier[:8]}",
                "id_token": "id-token",
            }

            steps: list[str] = []
            client = EmailOtpLoginClient()
            try:
                result = client.login(
                    "user@example.com",
                    {"providers": []},
                    {"address": "user@example.com"},
                    steps.append,
                )
            finally:
                client.close()

            called_urls = [item["url"] for item in fake_session.calls]
            self.assertTrue(any("/api/accounts/passwordless/send-otp" in url for url in called_urls))
            self.assertTrue(any("/api/accounts/email-otp/validate" in url for url in called_urls))
            self.assertFalse(any("/api/accounts/password/verify" in url for url in called_urls))

            passwordless_call = next(
                item for item in fake_session.calls if "/api/accounts/passwordless/send-otp" in item["url"]
            )
            self.assertEqual(passwordless_call["method"], "POST")
            self.assertEqual(
                passwordless_call["kwargs"]["headers"]["referer"],
                f"{batch_login_module.auth_base}/log-in/password",
            )
            self.assertIn("openai-sentinel-token", passwordless_call["kwargs"]["headers"])

            self.assertEqual(result["email"], "user@example.com")
            self.assertEqual(result["access_token"], "access:test-auth-code")
            self.assertIn("发送验证码", steps)
            self.assertTrue(fake_session.closed)
        finally:
            batch_login_module.create_session = original_create_session
            batch_login_module.mail_provider.remember_latest_message = original_remember_latest_message
            batch_login_module.mail_provider.wait_for_code = original_wait_for_code
            batch_login_module.build_sentinel_token_tuple = original_build_sentinel
            batch_login_module.request_platform_oauth_token = original_request_token

    def test_start_saves_existing_cloudflare_mail_options(self) -> None:
        fake = FakeRegisterService(
            {
                "proxy": "http://127.0.0.1:7890",
                "mail": {
                    "request_timeout": 30,
                    "wait_timeout": 120,
                    "wait_interval": 3,
                    "providers": [
                        {"type": "tempmail_lol", "enable": True, "api_key": "keep"},
                        {
                            "type": "cloudflare_temp_email",
                            "enable": False,
                            "api_base": "https://old.example.com",
                            "admin_password": "old-admin",
                            "custom_password": "old-custom",
                            "domain": ["example.com"],
                        },
                    ],
                },
            }
        )

        def run_test() -> None:
            service = BatchLoginService()
            captured: dict = {}
            completed = threading.Event()

            def fake_run(job_id, emails, mail_config, proxy):
                captured.update(
                    {
                        "job_id": job_id,
                        "emails": emails,
                        "mail_config": mail_config,
                        "proxy": proxy,
                    }
                )
                completed.set()

            service._run = fake_run
            service.start(
                ["user@example.com"],
                {
                    "api_base": " https://worker.example.com/ ",
                    "admin_password": " admin-secret ",
                    "custom_password": " custom-secret ",
                },
            )

            self.assertTrue(completed.wait(1.0))
            provider = fake.config["mail"]["providers"][1]
            self.assertEqual(fake.config["mail"]["providers"][0]["api_key"], "keep")
            self.assertTrue(provider["enable"])
            self.assertEqual(provider["api_base"], "https://worker.example.com/")
            self.assertEqual(provider["admin_password"], "admin-secret")
            self.assertEqual(provider["custom_password"], "custom-secret")
            self.assertEqual(provider["domain"], ["example.com"])
            self.assertEqual(captured["mail_config"]["providers"][0]["api_base"], "https://worker.example.com/")
            self.assertEqual(captured["proxy"], "http://127.0.0.1:7890")

        self.with_register_service(fake, run_test)

    def test_start_creates_cloudflare_provider_when_missing(self) -> None:
        fake = FakeRegisterService(
            {
                "proxy": "",
                "mail": {
                    "request_timeout": 30,
                    "wait_timeout": 120,
                    "wait_interval": 3,
                    "providers": [{"type": "tempmail_lol", "enable": True, "api_key": "keep"}],
                },
            }
        )

        def run_test() -> None:
            service = BatchLoginService()
            completed = threading.Event()
            service._run = lambda *_args: completed.set()
            service.start(
                ["user@example.com"],
                {
                    "api_base": "https://worker.example.com",
                    "admin_password": "admin-secret",
                    "custom_password": "",
                },
            )

            self.assertTrue(completed.wait(1.0))
            providers = fake.config["mail"]["providers"]
            self.assertEqual(len(providers), 2)
            self.assertEqual(providers[0]["type"], "tempmail_lol")
            self.assertEqual(providers[1]["type"], "cloudflare_temp_email")
            self.assertTrue(providers[1]["enable"])
            self.assertEqual(providers[1]["api_base"], "https://worker.example.com")
            self.assertEqual(providers[1]["admin_password"], "admin-secret")
            self.assertEqual(providers[1]["custom_password"], "")
            self.assertEqual(providers[1]["domain"], [])

        self.with_register_service(fake, run_test)

    def test_start_uses_and_saves_proxy_override(self) -> None:
        fake = FakeRegisterService(
            {
                "proxy": "http://old.example.com:7890",
                "mail": {
                    "request_timeout": 30,
                    "wait_timeout": 120,
                    "wait_interval": 3,
                    "proxy": "http://old.example.com:7890",
                    "providers": [
                        {
                            "type": "cloudflare_temp_email",
                            "enable": True,
                            "api_base": "https://worker.example.com",
                            "admin_password": "admin-secret",
                            "custom_password": "",
                            "domain": [],
                        }
                    ],
                },
            }
        )

        def run_test() -> None:
            service = BatchLoginService()
            captured: dict = {}
            completed = threading.Event()

            def fake_run(job_id, emails, mail_config, proxy):
                captured.update({"mail_config": mail_config, "proxy": proxy})
                completed.set()

            service._run = fake_run
            service.start(["user@example.com"], None, " http://127.0.0.1:7890 ")

            self.assertTrue(completed.wait(1.0))
            self.assertEqual(captured["proxy"], "http://127.0.0.1:7890")
            self.assertEqual(captured["mail_config"]["proxy"], "http://127.0.0.1:7890")
            self.assertEqual(fake.config["proxy"], "http://127.0.0.1:7890")

        self.with_register_service(fake, run_test)

    def test_start_empty_proxy_override_clears_saved_proxy(self) -> None:
        fake = FakeRegisterService(
            {
                "proxy": "http://old.example.com:7890",
                "mail": {
                    "request_timeout": 30,
                    "wait_timeout": 120,
                    "wait_interval": 3,
                    "proxy": "http://old.example.com:7890",
                    "providers": [
                        {
                            "type": "cloudflare_temp_email",
                            "enable": True,
                            "api_base": "https://worker.example.com",
                            "admin_password": "admin-secret",
                            "custom_password": "",
                            "domain": [],
                        }
                    ],
                },
            }
        )

        def run_test() -> None:
            service = BatchLoginService()
            captured: dict = {}
            completed = threading.Event()

            def fake_run(job_id, emails, mail_config, proxy):
                captured.update({"mail_config": mail_config, "proxy": proxy})
                completed.set()

            service._run = fake_run
            service.start(["user@example.com"], None, "")

            self.assertTrue(completed.wait(1.0))
            self.assertEqual(captured["proxy"], "")
            self.assertEqual(captured["mail_config"]["proxy"], "")
            self.assertEqual(fake.config["proxy"], "")
            self.assertEqual(fake.config["mail"]["proxy"], "")

        self.with_register_service(fake, run_test)


if __name__ == "__main__":
    unittest.main()
