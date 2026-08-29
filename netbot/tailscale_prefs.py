"""Small capability-based observer for the local Tailscale SSH preference."""

from dataclasses import dataclass
import json
from typing import Callable, Any


@dataclass(frozen=True)
class PreferenceObservation:
    state: str
    ssh: bool | None
    source: str
    detail: str | None = None


def parse_preference(provider: str, returncode: int, stdout: str = "", stderr: str = "") -> PreferenceObservation:
    """Parse one supported read-only provider without treating failure as false."""
    if returncode != 0:
        return PreferenceObservation("unsupported" if "unknown" in (stderr or stdout).lower() or "unrecognized" in (stderr or stdout).lower() else "unavailable", None, provider, (stderr or stdout).strip() or None)
    try:
        payload = json.loads(stdout)
    except (TypeError, ValueError):
        return PreferenceObservation("unknown", None, provider, "invalid structured preference output")
    value = payload.get("ssh") if provider == "tailscale get --json" else payload.get("RunSSH")
    if value is True or value is False:
        return PreferenceObservation("observed", value, provider)
    return PreferenceObservation("unknown", None, provider, "SSH preference was not present or boolean")


class TailscalePreferenceObserver:
    """Try the strongest supported read-only interface, then the fallback."""

    def __init__(self, run: Callable[[str], Any]):
        self.run = run

    def observe(self) -> PreferenceObservation:
        first = self.run("tailscale get --json")
        parsed = parse_preference("tailscale get --json", first.get("returncode", 255), first.get("stdout", ""), first.get("stderr", ""))
        if parsed.state == "observed":
            return parsed
        fallback = self.run("tailscale debug prefs")
        second = parse_preference("tailscale debug prefs (RunSSH)", fallback.get("returncode", 255), fallback.get("stdout", ""), fallback.get("stderr", ""))
        if second.state == "observed":
            return second
        return PreferenceObservation(second.state if second.state in {"unknown", "unavailable", "unsupported"} else parsed.state,
                                     None, second.source, second.detail or parsed.detail)
