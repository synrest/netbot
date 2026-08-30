from pathlib import Path
from .models import DesiredHost

def _scalar(value: str):
    value = value.strip()
    if not value: return None
    if value in ("null", "~"): return None
    if value.lower() in ("true", "false"): return value.lower() == "true"
    if value.startswith("[") and value.endswith("]"):
        return [x.strip().strip("'\"") for x in value[1:-1].split(",") if x.strip()]
    return value.strip("'\"")

def load_topology(path: Path) -> tuple[int, list[DesiredHost]]:
    # Deliberately small parser for the stable, dependency-free topology subset.
    version = 1; hosts: list[DesiredHost] = []; current = None; pending_list = None; section = "none"
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip(): continue
        indent = len(line) - len(line.lstrip())
        text = line.strip()
        if indent == 0 and text.startswith("version:"):
            version = int(text.split(":", 1)[1].strip())
        elif indent == 0 and text == "hosts:":
            section = "hosts"
        elif indent == 0 and text == "agents:":
            section = "agents"
        elif section != "hosts":
            continue
        elif indent == 2 and text.endswith(":"):
            current = DesiredHost(text[:-1]); hosts.append(current); pending_list = None
        elif indent == 4 and current and text == "bindings:":
            current.attrs["bindings"] = {}; pending_list = None
        elif indent == 6 and current and current.attrs.get("bindings") is not None and text.endswith(":"):
            current.attrs["bindings"][text[:-1]] = {}; pending_list = None
        elif indent == 8 and current and current.attrs.get("bindings") is not None and ":" in text:
            key, val = text.split(":", 1); key = key.strip(); val = val.strip()
            target = current.attrs["bindings"].get("tailscale", {}) if key in ("node_id", "name") else current.attrs["bindings"].setdefault("ssh", {})
            if val: target[key] = _scalar(val); pending_list = None
            else: target[key] = []; pending_list = key
        elif indent == 10 and current and current.attrs.get("bindings") is not None and text.startswith("-") and pending_list:
            current.attrs["bindings"].setdefault("ssh", {}).setdefault(pending_list, []).append(_scalar(text[1:].strip()))
        elif indent == 4 and current and ":" in text:
            key, val = text.split(":", 1); key = key.strip(); val = val.strip()
            if val: current.attrs[key] = _scalar(val); pending_list = None
            else: current.attrs[key] = []; pending_list = key
        elif indent == 6 and text.startswith("-") and current and pending_list:
            current.attrs[pending_list].append(_scalar(text[1:].strip()))
    return version, hosts


def load_topology_authority(path: Path) -> str | None:
    """Read the single explicit snapshot authority identity, if declared."""
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if line and len(line) - len(line.lstrip()) == 0 and line.startswith("authority:"):
            value = _scalar(line.split(":", 1)[1])
            return str(value) if value is not None else None
    return None


def load_agent_settings(path: Path) -> dict:
    """Read the intentionally small global agent settings subset."""
    settings = {}
    section = None
    subsection = None
    for raw in path.read_text().splitlines():
        text = raw.split("#", 1)[0].strip()
        if not text:
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent == 0 and text == "agents:":
            section = "agents"; subsection = None
        elif indent == 2 and section == "agents" and text == "temporary:":
            subsection = "temporary"
        elif indent == 4 and subsection == "temporary" and text.startswith("desired_version:"):
            settings["temporary_desired_version"] = _scalar(text.split(":", 1)[1])
    return settings
