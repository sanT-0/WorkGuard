"""WorkGuard Windows Endpoint Agent Simulator (development harness).

This is *not* the Windows service.  It exercises the real control-plane
contract: device-token authentication, SIGNING_SPEC envelope verification,
schema validation, read-back result reporting and event upload.  Enforcement
results are simulated and labelled as such.

Usage:
    python simulator.py sync
    python simulator.py heartbeat
    python simulator.py usb
    python simulator.py enroll WG-...
    python simulator.py daemon
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTROL_API = HERE.parent / "control-api"
sys.path.insert(0, str(CONTROL_API))

try:
    from app.policy_verify import PolicyVerificationError, verify_envelope
    from app.validation import validate_policy
except Exception as exc:  # noqa: BLE001
    print(f"[FATAL] Shared verification modules are unavailable: {exc}")
    print("Install control-api/requirements.txt and run from the repository.")
    raise SystemExit(2) from exc

SERVER_URL = os.getenv("WG_SERVER_URL", "http://127.0.0.1:8000/api/v1").rstrip("/")
IDENTITY_FILE = Path(
    os.getenv("WG_IDENTITY_FILE", str(HERE / "agent_identity.json"))
)
TOKEN_FILE = Path(
    os.getenv(
        "WG_DEVICE_TOKEN_FILE",
        str(CONTROL_API / ".dev-device-tokens.json"),
    )
)
DEFAULT_DEVICE_ID = os.getenv("WG_DEVICE_ID", "dev-sim-001")


def _iso_now() -> str:
    return datetime.now(UTC).isoformat()


class WorkGuardAgent:
    def __init__(self, device_id: str | None = None, server_url: str = SERVER_URL):
        self.server_url = server_url
        self.device_id = device_id or DEFAULT_DEVICE_ID
        self.os_version = "Windows 11 Enterprise (23H2)"
        self.os_edition = "Windows 11 Enterprise"
        self.agent_version = "1.1.0"
        self.device_token: str | None = None
        self.last_applied_version = 0
        self.last_envelope: dict | None = None
        self.load_identity()

    # ------------------------------------------------------------------ state
    def load_identity(self) -> None:
        if IDENTITY_FILE.exists():
            try:
                data = json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))
                self.device_id = data.get("device_id", self.device_id)
                self.device_token = data.get("device_token")
                self.last_applied_version = int(data.get("last_applied_version", 0))
                self.last_envelope = data.get("last_envelope")
            except Exception:  # noqa: BLE001
                pass

        if not self.device_token and TOKEN_FILE.exists():
            try:
                tokens = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
                self.device_token = tokens.get(self.device_id)
            except Exception:  # noqa: BLE001
                pass

    def save_identity(self) -> None:
        IDENTITY_FILE.write_text(
            json.dumps(
                {
                    "device_id": self.device_id,
                    "device_token": self.device_token,
                    "last_applied_version": self.last_applied_version,
                    "last_envelope": self.last_envelope,
                    "saved_at": _iso_now(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        try:
            os.chmod(IDENTITY_FILE, 0o600)
        except OSError:
            pass

    # ------------------------------------------------------------------- HTTP
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.device_token:
            headers["Authorization"] = f"Bearer {self.device_token}"
        return headers

    def _http_post(self, path: str, payload: dict | None = None):
        data = json.dumps(payload or {}).encode("utf-8")
        request = urllib.request.Request(
            f"{self.server_url}{path}",
            data=data,
            headers=self._headers(),
            method="POST",
        )
        return self._send(request)

    def _http_get(self, path: str):
        request = urllib.request.Request(
            f"{self.server_url}{path}",
            headers=self._headers(),
            method="GET",
        )
        return self._send(request)

    def _send(self, request: urllib.request.Request):
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                body = response.read().decode("utf-8")
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8")
            try:
                parsed = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed = {"detail": body}
            return exc.code, parsed
        except Exception as exc:  # noqa: BLE001
            return 0, {"error": str(exc)}

    # -------------------------------------------------------------- enrolment
    def enroll(self, enrollment_code: str) -> bool:
        print(f"[*] Enrolling {self.device_id} with a one-time code...")
        status, response = self._http_post(
            "/agent/enroll",
            {
                "enrollment_code": enrollment_code.strip(),
                "agent_version": self.agent_version,
                "os_version": self.os_version,
                "os_edition": self.os_edition,
            },
        )
        if status != 201:
            print(f"[-] Enrollment failed ({status}): {response}")
            return False

        self.device_id = response["device_id"]
        self.device_token = response["device_token"]
        self.last_applied_version = 0
        self.last_envelope = None
        self.save_identity()
        print(f"[+] Enrolled. Device ID: {self.device_id}")
        print("    Store the device token securely; it is shown once.")
        return True

    # -------------------------------------------------------------- heartbeat
    def send_heartbeat(self) -> bool:
        if not self.device_token:
            print("[-] No device token. Run: python simulator.py enroll WG-...")
            return False
        status, response = self._http_post(
            "/agent/heartbeat",
            {
                "agent_version": self.agent_version,
                "os_version": self.os_version,
                "os_edition": self.os_edition,
                "current_policy_version": self.last_applied_version or None,
                "observed_at": _iso_now(),
                "endpoint_protection_state": "unknown",
            },
        )
        if status == 202:
            print(f"[+] Heartbeat acknowledged: {response.get('last_seen_at')}")
            return True
        print(f"[-] Heartbeat rejected ({status}): {response}")
        return False

    # -------------------------------------------------------------- policy
    def _jwks(self) -> dict:
        status, response = self._http_get("/agent/keys")
        if status != 200:
            raise PolicyVerificationError(f"JWKS fetch failed ({status})")
        return response

    def fetch_and_apply_policy(self) -> bool:
        if not self.device_token:
            print("[-] No device token. Run: python simulator.py enroll WG-...")
            return False

        status, envelope = self._http_get("/agent/policies/current")
        if status == 204:
            print("[*] Control plane has no published policy for this device.")
            return True
        if status != 200:
            print(f"[-] Policy fetch failed ({status}): {envelope}")
            return False

        try:
            jwks = self._jwks()
            verified = verify_envelope(
                envelope,
                jwks,
                self.device_id,
                last_applied_version=self.last_applied_version,
            )
            validate_policy(verified.policy)
        except Exception as exc:  # noqa: BLE001
            print(f"[!] POLICY REJECTED: {exc}")
            self._report_event(
                "policy.rejected",
                "high",
                "policy_verifier",
                "rejected",
            )
            return False

        policy = verified.policy
        print(
            f"[+] Verified policy '{policy['name']}' v{verified.policy_version} "
            f"(kid={verified.key_id}, digest={envelope['digest_sha256'][:16]}...)"
        )

        results = self._simulate_readback(policy)
        result_status, result_body = self._http_post(
            "/agent/policy-results",
            {
                "policy_version": verified.policy_version,
                "observed_at": _iso_now(),
                "controls": results,
            },
        )
        if result_status != 202:
            print(f"[-] Policy results rejected ({result_status}): {result_body}")
            return False

        self.last_applied_version = verified.policy_version
        self.last_envelope = envelope
        self.save_identity()
        print(
            "[+] Read-back results accepted. Derived device status: "
            f"{result_body.get('derived_device_status')}"
        )
        return True

    def _simulate_readback(self, policy: dict) -> list[dict]:
        """Simulation only.  The real service reads each provider's state."""

        now = _iso_now()
        results = []
        for control in policy.get("controls", []):
            control_id = control["control_id"]
            status = "enforced"
            provider = "Simulated Windows provider"
            error_code = None
            details = "Simulated read-back; not evidence from a real endpoint"

            if control_id == "removable_storage":
                provider = "Windows Defender Removable Storage Filter (simulated)"
            elif control_id == "disk_encryption":
                provider = "BitLocker CSP AES-256-XTS (simulated)"
            elif control_id == "application_control":
                provider = "AppLocker / App Control for Business (simulated)"
                if "Pro" in self.os_edition:
                    status = "unsupported"
                    error_code = "EDITION_UNSUPPORTED"
                    details = "AppLocker requires Windows Enterprise edition"
            elif control_id == "endpoint_protection":
                provider = "Microsoft Defender Antivirus (simulated)"
            elif control_id == "network_policy":
                provider = "Windows Advanced Firewall (simulated)"
            elif control_id == "endpoint_dlp":
                status = "not_configured"
                error_code = "DLP_PROVIDER_NOT_CONFIGURED"
                details = "No endpoint DLP integration is configured in this proof of concept"

            results.append(
                {
                    "control_id": control_id,
                    "status": status,
                    "provider": provider,
                    "observed_at": now,
                    "error_code": error_code,
                    "safe_details": details,
                }
            )
        return results

    # ---------------------------------------------------------------- events
    def _report_event(
        self, event_type: str, severity: str, source: str, response_state: str
    ) -> bool:
        status, response = self._http_post(
            "/agent/events:batch",
            {
                "events": [
                    {
                        "event_type": event_type,
                        "severity": severity,
                        "occurred_at": _iso_now(),
                        "source": source,
                        "response_state": response_state,
                    }
                ]
            },
        )
        if status != 202:
            print(f"[-] Event upload failed ({status}): {response}")
            return False
        return True

    def simulate_usb_block(self) -> bool:
        print(f"[*] Simulating a blocked USB storage insertion on {self.device_id}...")
        ok = self._report_event(
            "usb.device.blocked", "high", "removable_storage", "blocked"
        )
        if ok:
            print("[+] Blocked event accepted by the control plane.")
        return ok

    # ---------------------------------------------------------------- daemon
    def daemon(self) -> None:
        print("[*] Starting simulator daemon (Ctrl+C to stop)...")
        self.send_heartbeat()
        self.fetch_and_apply_policy()
        while True:
            time.sleep(60)
            self.send_heartbeat()
            self.fetch_and_apply_policy()


def main() -> None:
    agent = WorkGuardAgent()
    print("=" * 68)
    print("       WorkGuard Endpoint Agent Simulator (verification harness)")
    print(f"       Device: {agent.device_id}")
    print(f"       API:    {agent.server_url}")
    print(f"       Token:  {'configured' if agent.device_token else 'MISSING'}")
    print("=" * 68)

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        if command == "heartbeat":
            agent.send_heartbeat()
        elif command == "sync":
            agent.send_heartbeat()
            agent.fetch_and_apply_policy()
        elif command == "usb":
            agent.simulate_usb_block()
        elif command == "enroll" and len(sys.argv) > 2:
            agent.enroll(sys.argv[2])
        elif command == "daemon":
            agent.daemon()
        else:
            print("Unknown command. Use: heartbeat | sync | usb | enroll <code> | daemon")
        return

    while True:
        print("\n1. Heartbeat")
        print("2. Fetch, verify and apply policy")
        print("3. Simulate blocked USB insertion")
        print("4. Enroll with one-time code")
        print("5. Full cycle")
        print("0. Exit")
        choice = input("Select [0-5]: ").strip()
        if choice == "1":
            agent.send_heartbeat()
        elif choice == "2":
            agent.fetch_and_apply_policy()
        elif choice == "3":
            agent.simulate_usb_block()
        elif choice == "4":
            code = input("Enrollment code: ").strip()
            agent.enroll(code)
        elif choice == "5":
            agent.send_heartbeat()
            agent.fetch_and_apply_policy()
            agent.simulate_usb_block()
        elif choice == "0":
            break


if __name__ == "__main__":
    main()
