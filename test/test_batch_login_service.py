from __future__ import annotations

import copy
import threading
import unittest

from services import batch_login_service as batch_login_module
from services.batch_login_service import BatchLoginService


class FakeRegisterService:
    def __init__(self, config: dict):
        self.config = copy.deepcopy(config)
        self.updates: list[dict] = []

    def get(self) -> dict:
        return copy.deepcopy(self.config)

    def update(self, updates: dict) -> dict:
        self.updates.append(copy.deepcopy(updates))
        self.config.update(copy.deepcopy(updates))
        return self.get()


class BatchLoginServiceTests(unittest.TestCase):
    def with_register_service(self, fake: FakeRegisterService, callback):
        original = batch_login_module.register_service
        try:
            batch_login_module.register_service = fake
            return callback()
        finally:
            batch_login_module.register_service = original

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


if __name__ == "__main__":
    unittest.main()
