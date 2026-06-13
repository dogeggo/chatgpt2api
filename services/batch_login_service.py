from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qs, urlencode, urlparse

from services.account_service import account_service
from services.register import mail_provider
from services.register.openai_register import (
    _is_cloudflare_challenge,
    _response_debug_detail,
    _response_json,
    auth_base,
    common_headers,
    create_session,
    extract_oauth_callback_params_from_url,
    navigate_headers,
    platform_auth0_client,
    platform_base,
    platform_oauth_audience,
    platform_oauth_client_id,
    platform_oauth_redirect_uri,
    request_platform_oauth_token,
    request_with_local_retry,
    sec_ch_ua,
    user_agent,
)
from services.register_service import register_service
from utils.helper import anonymize_token
from utils.pkce import generate_pkce
from utils.sentinel import build_sentinel_token as build_sentinel_token_tuple


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_trace_headers() -> dict[str, str]:
    trace_id = str(uuid.uuid4().int >> 64)
    parent_id = str(uuid.uuid4().int >> 64)
    return {
        "traceparent": f"00-{uuid.uuid4().hex}-{int(parent_id):016x}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def _safe_json(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False, default=str))


def _normalize_emails(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        for line in str(value or "").splitlines():
            email = line.strip()
            if not email:
                continue
            key = email.lower()
            if key in seen:
                continue
            if not EMAIL_RE.match(email):
                raise ValueError(f"邮箱格式不正确: {email}")
            seen.add(key)
            result.append(email)
    return result


class EmailOtpLoginClient:
    def __init__(self, proxy: str = "") -> None:
        self.session = create_session(proxy)
        self.device_id = str(uuid.uuid4())
        self.code_verifier = ""
        self.email_verification_url = ""
        self.passwordless_login_url = ""

    def close(self) -> None:
        self.session.close()

    def _navigate_headers(self, referer: str = "") -> dict[str, str]:
        headers = dict(navigate_headers)
        if referer:
            headers["referer"] = referer
        return headers

    def _json_headers(self, referer: str) -> dict[str, str]:
        headers = dict(common_headers)
        headers["referer"] = referer
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        return headers

    def _authorize(self, email: str) -> str:
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        self.email_verification_url = ""
        self.passwordless_login_url = ""
        self.code_verifier, code_challenge = generate_pkce()
        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": platform_oauth_redirect_uri,
            "device_id": self.device_id,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "login_hint": email,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": platform_auth0_client,
        }
        resp, error = request_with_local_retry(
            self.session,
            "get",
            f"{auth_base}/api/accounts/authorize?{urlencode(params)}",
            headers=self._navigate_headers(f"{platform_base}/"),
            allow_redirects=True,
            verify=False,
        )
        if resp is not None and _is_cloudflare_challenge(resp):
            raise RuntimeError("被 Cloudflare 拦截，请更换 IP 重试")
        if resp is None or resp.status_code not in (200, 302):
            status = getattr(resp, "status_code", "unknown")
            debug = _response_debug_detail(resp)
            raise RuntimeError(error or f"platform_authorize_http_{status}, {debug}")

        final_url = str(getattr(resp, "url", "") or "")
        if "/email-verification" in final_url:
            self.email_verification_url = final_url
        if "/log-in/password" in final_url:
            self.passwordless_login_url = final_url
        if "/error" in final_url and "payload=" in final_url:
            try:
                parsed_query = parse_qs(urlparse(final_url).query)
                error_payload_b64 = parsed_query.get("payload", [""])[0]
                error_payload_b64 += "=" * ((4 - len(error_payload_b64) % 4) % 4)
                error_payload = json.loads(base64.b64decode(error_payload_b64))
                error_code = str(error_payload.get("errorCode") or "unknown")
                raise RuntimeError(f"authorize_error_{error_code}: {json.dumps(error_payload, ensure_ascii=False)[:500]}")
            except RuntimeError:
                raise
            except Exception as exc:
                raise RuntimeError(f"authorize_redirect_error: {final_url[:300]}, parse_error={exc}") from exc

        callback_params = extract_oauth_callback_params_from_url(final_url)
        auth_code = str((callback_params or {}).get("code") or "").strip()
        if not auth_code and not self.email_verification_url and not self.passwordless_login_url:
            debug = _response_debug_detail(resp)
            raise RuntimeError(f"OpenAI 未进入邮箱验证码或一次性验证码登录步骤，无法发送验证码: {debug}")
        return auth_code

    def _otp_referer(self) -> str:
        return self.email_verification_url or f"{auth_base}/email-verification"

    def _passwordless_referer(self) -> str:
        return self.passwordless_login_url or f"{auth_base}/log-in/password"

    def _raise_for_error_redirect(self, final_url: str) -> None:
        if "/error" not in final_url or "payload=" not in final_url:
            return
        try:
            parsed_query = parse_qs(urlparse(final_url).query)
            error_payload_b64 = parsed_query.get("payload", [""])[0]
            error_payload_b64 += "=" * ((4 - len(error_payload_b64) % 4) % 4)
            error_payload = json.loads(base64.b64decode(error_payload_b64))
            error_code = str(error_payload.get("errorCode") or "unknown")
            raise RuntimeError(f"send_otp_error_{error_code}: {json.dumps(error_payload, ensure_ascii=False)[:500]}")
        except RuntimeError:
            raise
        except Exception as exc:
            raise RuntimeError(f"send_otp_redirect_error: {final_url[:300]}, parse_error={exc}") from exc

    def _handle_send_otp_response(self, resp: Any, error: str, label: str) -> str:
        if resp is None or resp.status_code not in (200, 202, 204, 302):
            body = str(getattr(resp, "text", "") or "")[:500] if resp is not None else ""
            raise RuntimeError(error or f"{label}_http_{getattr(resp, 'status_code', 'unknown')}_body={body}")
        if _is_cloudflare_challenge(resp):
            raise RuntimeError("发送验证码被 Cloudflare 拦截，请更换 IP 重试")

        final_url = str(getattr(resp, "url", "") or "")
        self._raise_for_error_redirect(final_url)

        data = _response_json(resp)
        if isinstance(data, dict):
            error_value = data.get("error") or data.get("errorCode") or data.get("error_code")
            if error_value:
                raise RuntimeError(f"{label}_error: {json.dumps(data, ensure_ascii=False)[:500]}")
            continue_url = str(data.get("continue_url") or "").strip()
            if "/email-verification" in continue_url:
                self.email_verification_url = continue_url

        if "/email-verification" in final_url:
            self.email_verification_url = final_url

        return f"HTTP {resp.status_code}"

    def _send_passwordless_otp(self) -> str:
        headers = self._json_headers(self._passwordless_referer())
        sentinel_val, oai_sc_val = build_sentinel_token_tuple(
            self.session,
            self.device_id,
            "password_verify",
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
        )
        headers["openai-sentinel-token"] = sentinel_val
        if oai_sc_val:
            self.session.cookies.set("oai-sc", oai_sc_val, domain=".openai.com")

        resp, error = request_with_local_retry(
            self.session,
            "post",
            f"{auth_base}/api/accounts/passwordless/send-otp",
            headers=headers,
            verify=False,
        )
        return self._handle_send_otp_response(resp, error, "passwordless_send_otp")

    def _send_email_otp(self) -> str:
        referer = self._otp_referer()
        headers = self._json_headers(referer)
        headers["accept"] = "*/*"
        resp, error = request_with_local_retry(
            self.session,
            "get",
            f"{auth_base}/api/accounts/email-otp/send",
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        return self._handle_send_otp_response(resp, error, "send_otp")

    def _send_otp(self) -> str:
        if self.passwordless_login_url:
            return self._send_passwordless_otp()
        if self.email_verification_url:
            return self._send_email_otp()
        raise RuntimeError("OpenAI 未进入邮箱验证码或一次性验证码登录步骤，无法发送验证码")

    def _validate_otp(self, code: str) -> tuple[dict[str, Any], str]:
        headers = self._json_headers(self._otp_referer())
        resp, error = request_with_local_retry(
            self.session,
            "post",
            f"{auth_base}/api/accounts/email-otp/validate",
            json={"code": code},
            headers=headers,
            verify=False,
        )

        if resp is None or resp.status_code != 200:
            headers = self._json_headers(self._otp_referer())
            sentinel_val, oai_sc_val = build_sentinel_token_tuple(
                self.session,
                self.device_id,
                "authorize_continue",
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
            )
            headers["openai-sentinel-token"] = sentinel_val
            if oai_sc_val:
                self.session.cookies.set("oai-sc", oai_sc_val, domain=".openai.com")
            resp, error = request_with_local_retry(
                self.session,
                "post",
                f"{auth_base}/api/accounts/email-otp/validate",
                json={"code": code},
                headers=headers,
                verify=False,
            )

        if resp is None or resp.status_code != 200:
            body = str(getattr(resp, "text", "") or "")[:500] if resp is not None else ""
            raise RuntimeError(error or f"validate_otp_http_{getattr(resp, 'status_code', 'unknown')}_body={body}")

        return _response_json(resp), str(getattr(resp, "url", "") or "")

    def _extract_auth_code(self, payload: Any, response_url: str = "") -> str:
        direct = extract_oauth_callback_params_from_url(response_url)
        if direct and direct.get("code"):
            return str(direct["code"]).strip()

        stack = [payload]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                for key, item in value.items():
                    key_text = str(key or "").lower()
                    if isinstance(item, str):
                        parsed = extract_oauth_callback_params_from_url(item)
                        if parsed and parsed.get("code"):
                            return str(parsed["code"]).strip()
                        if key_text in {"code", "authorization_code", "auth_code"} and len(item.strip()) > 20:
                            return item.strip()
                    elif isinstance(item, (dict, list)):
                        stack.append(item)
            elif isinstance(value, list):
                stack.extend(value)
        return ""

    def login(
        self,
        email: str,
        mailbox_config: dict,
        mailbox: dict,
        on_step: Callable[[str], None],
    ) -> dict[str, Any]:
        on_step("发起授权")
        auth_code = self._authorize(email)
        if not auth_code:
            on_step("清理历史邮件")
            mail_provider.remember_latest_message(mailbox_config, mailbox)
            on_step("发送验证码")
            send_result = self._send_otp()
            on_step(f"验证码发送请求完成: {send_result}")
            on_step("等待验证码")
            code = mail_provider.wait_for_code(mailbox_config, mailbox)
            if not code:
                raise RuntimeError("等待登录验证码超时，发送请求已返回但邮箱未收到新验证码")
            on_step("校验验证码")
            payload, response_url = self._validate_otp(code)
            auth_code = self._extract_auth_code(payload, response_url)
            if not auth_code:
                detail = json.dumps(payload, ensure_ascii=False)[:800] if payload else ""
                raise RuntimeError(f"验证码已校验，但 OpenAI 未返回授权码{': ' + detail if detail else ''}")

        on_step("换取 token")
        tokens = request_platform_oauth_token(self.session, auth_code, self.code_verifier)
        if not tokens or not tokens.get("access_token"):
            raise RuntimeError("token 换取失败")

        return {
            "email": email,
            "access_token": str(tokens.get("access_token") or "").strip(),
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "id_token": str(tokens.get("id_token") or "").strip(),
            "source_type": "batch_login",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }


class BatchLoginService:
    _MAX_JOBS = 20

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, dict[str, Any]] = {}

    def _purge_locked(self) -> None:
        if len(self._jobs) <= self._MAX_JOBS:
            return
        ordered = sorted(self._jobs.items(), key=lambda item: str(item[1].get("created_at") or ""))
        for job_id, _ in ordered[: len(self._jobs) - self._MAX_JOBS]:
            self._jobs.pop(job_id, None)

    @staticmethod
    def _clean(value: Any) -> str:
        return str(value or "").strip()

    def _has_cloudflare_mail_options(self, options: dict[str, Any] | None) -> bool:
        return isinstance(options, dict) and any(
            self._clean(options.get(key))
            for key in ("api_base", "admin_password", "custom_password")
        )

    def _cloudflare_provider_from_options(self, raw_mail: dict[str, Any], options: dict[str, Any] | None) -> dict[str, Any] | None:
        if not self._has_cloudflare_mail_options(options):
            return None

        base_provider = next(
            (
                item
                for item in raw_mail.get("providers", [])
                if isinstance(item, dict)
                and item.get("enable")
                and self._clean(item.get("type")) == "cloudflare_temp_email"
            ),
            {},
        )
        provider = {
            **base_provider,
            "type": "cloudflare_temp_email",
            "enable": True,
        }
        for key in ("api_base", "admin_password", "custom_password"):
            if key in options:
                provider[key] = self._clean(options.get(key))
        return provider

    def _save_cloudflare_mail_options(self, mail_options: dict[str, Any] | None) -> None:
        if not self._has_cloudflare_mail_options(mail_options):
            return

        cfg = register_service.get()
        raw_mail = cfg.get("mail") if isinstance(cfg.get("mail"), dict) else {}
        providers = [
            dict(item)
            for item in raw_mail.get("providers", [])
            if isinstance(item, dict)
        ]
        target_index = next(
            (
                index
                for index, item in enumerate(providers)
                if item.get("enable")
                and self._clean(item.get("type")) == "cloudflare_temp_email"
            ),
            None,
        )
        if target_index is None:
            target_index = next(
                (
                    index
                    for index, item in enumerate(providers)
                    if self._clean(item.get("type")) == "cloudflare_temp_email"
                ),
                None,
            )
        if target_index is None:
            providers.append(
                {
                    "type": "cloudflare_temp_email",
                    "enable": True,
                    "api_base": "",
                    "admin_password": "",
                    "custom_password": "",
                    "domain": [],
                }
            )
            target_index = len(providers) - 1

        provider = {
            **providers[target_index],
            "type": "cloudflare_temp_email",
            "enable": True,
        }
        for key in ("api_base", "admin_password", "custom_password"):
            if key in mail_options:
                provider[key] = self._clean(mail_options.get(key))
        provider.setdefault("domain", [])
        providers[target_index] = provider

        register_service.update({"mail": {**raw_mail, "providers": providers}})

    def _load_cloudflare_mail_config(
        self,
        mail_options: dict[str, Any] | None = None,
        proxy_override: str | None = None,
    ) -> tuple[dict[str, Any], str]:
        cfg = register_service.get()
        raw_mail = cfg.get("mail") if isinstance(cfg.get("mail"), dict) else {}
        option_provider = self._cloudflare_provider_from_options(raw_mail, mail_options)
        if option_provider:
            providers = [option_provider]
        else:
            providers = [
                {**item, "enable": True}
                for item in raw_mail.get("providers", [])
                if isinstance(item, dict)
                and item.get("enable")
                and self._clean(item.get("type")) == "cloudflare_temp_email"
            ]
        if not providers:
            raise ValueError("请先在注册机邮箱配置中启用 cloudflare_temp_email")

        for index, provider in enumerate(providers, start=1):
            if not self._clean(provider.get("api_base")):
                raise ValueError(f"cloudflare_temp_email#{index} 缺少 API Base")
            if not self._clean(provider.get("admin_password")):
                raise ValueError(f"cloudflare_temp_email#{index} 缺少 Admin Password")

        has_proxy_override = proxy_override is not None
        proxy = self._clean(proxy_override) if has_proxy_override else self._clean(cfg.get("proxy"))
        mail_config = {
            **raw_mail,
            "providers": providers,
            "proxy": proxy if has_proxy_override else proxy or str(raw_mail.get("proxy") or "").strip(),
        }
        return mail_config, proxy

    def start(
        self,
        emails: list[str],
        mail_options: dict[str, Any] | None = None,
        proxy: str | None = None,
    ) -> dict[str, Any]:
        normalized_emails = _normalize_emails(emails)
        if not normalized_emails:
            raise ValueError("邮箱列表不能为空")
        mail_config, resolved_proxy = self._load_cloudflare_mail_config(mail_options, proxy)
        self._save_cloudflare_mail_options(mail_options)
        if proxy is not None:
            register_service.update({"proxy": resolved_proxy})
        job_id = uuid.uuid4().hex
        job = {
            "job_id": job_id,
            "total": len(normalized_emails),
            "processed": 0,
            "success": 0,
            "fail": 0,
            "done": False,
            "error": None,
            "current_email": "",
            "current_step": "",
            "provider": "cloudflare_temp_email",
            "created_at": _now(),
            "updated_at": _now(),
            "items": [],
            "logs": [],
        }
        with self._lock:
            self._purge_locked()
            self._jobs[job_id] = job

        runner = threading.Thread(
            target=self._run,
            args=(job_id, normalized_emails, mail_config, resolved_proxy),
            daemon=True,
            name=f"batch-login-{job_id[:8]}",
        )
        runner.start()
        return self.get(job_id) or job

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(str(job_id or "").strip())
            return _safe_json(job) if job else None

    def _set_current(self, job_id: str, email: str, step: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["current_email"] = email
            job["current_step"] = step
            job["updated_at"] = _now()
            logs = job.setdefault("logs", [])
            logs.append({"time": _now(), "email": email, "level": "info", "text": step})
            job["logs"] = logs[-200:]

    def _finish_item(
        self,
        job_id: str,
        email: str,
        status: str,
        *,
        token: str = "",
        error: str | None = None,
        message: str = "",
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["processed"] = int(job.get("processed") or 0) + 1
            if status == "成功":
                job["success"] = int(job.get("success") or 0) + 1
            else:
                job["fail"] = int(job.get("fail") or 0) + 1
            job["items"].append(
                {
                    "email": email,
                    "status": status,
                    "token": token,
                    "error": error,
                    "message": message,
                    "finished_at": _now(),
                }
            )
            logs = job.setdefault("logs", [])
            logs.append(
                {
                    "time": _now(),
                    "email": email,
                    "level": "green" if status == "成功" else "red",
                    "text": message or error or status,
                }
            )
            job["logs"] = logs[-200:]
            job["current_email"] = "" if job["processed"] >= job["total"] else job.get("current_email", "")
            job["current_step"] = "" if job["processed"] >= job["total"] else job.get("current_step", "")
            job["done"] = job["processed"] >= job["total"]
            job["updated_at"] = _now()

    def _finish_job_error(self, job_id: str, error: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["done"] = True
            job["error"] = error
            job["current_email"] = ""
            job["current_step"] = ""
            job["updated_at"] = _now()

    def _mailbox_for_email(self, mail_config: dict[str, Any], email: str) -> tuple[dict[str, Any], dict[str, Any]]:
        errors: list[str] = []
        providers = [item for item in mail_config.get("providers", []) if isinstance(item, dict)]
        for index, provider in enumerate(providers, start=1):
            single_config = {**mail_config, "providers": [provider]}
            try:
                return mail_provider.get_existing_mailbox(single_config, email), single_config
            except Exception as exc:
                errors.append(f"cloudflare_temp_email#{index}: {exc}")
        raise RuntimeError("; ".join(errors) or f"无法获取邮箱 {email} 的 cloudflare_temp_email JWT")

    def _run(self, job_id: str, emails: list[str], mail_config: dict[str, Any], proxy: str) -> None:
        try:
            for email in emails:
                start = time.time()
                try:
                    self._set_current(job_id, email, "获取邮箱访问令牌")
                    mailbox, mailbox_config = self._mailbox_for_email(mail_config, email)
                    client = EmailOtpLoginClient(proxy)
                    try:
                        payload = client.login(
                            email,
                            mailbox_config,
                            mailbox,
                            lambda step, current=email: self._set_current(job_id, current, step),
                        )
                    finally:
                        client.close()

                    access_token = str(payload.get("access_token") or "").strip()
                    if not access_token:
                        raise RuntimeError("OpenAI 返回的 access_token 为空")

                    self._set_current(job_id, email, "保存账号")
                    account_service.add_account_items([payload])

                    warning = ""
                    self._set_current(job_id, email, "刷新账号状态")
                    refresh_result = account_service.refresh_accounts([access_token])
                    if refresh_result.get("errors"):
                        warning = f"登录成功，刷新状态暂未成功: {refresh_result['errors']}"

                    cost = time.time() - start
                    self._finish_item(
                        job_id,
                        email,
                        "成功",
                        token=anonymize_token(access_token),
                        message=warning or f"登录成功，用时 {cost:.1f}s",
                    )
                except Exception as exc:
                    self._finish_item(job_id, email, "失败", error=str(exc), message=str(exc))
        except Exception as exc:
            self._finish_job_error(job_id, str(exc))


batch_login_service = BatchLoginService()
