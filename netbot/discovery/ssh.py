from pathlib import Path
import re, subprocess
from ..models import SSHHost

def inspect_ssh(home: Path, exclude_managed=True) -> tuple[list[SSHHost], list[dict]]:
    config = home / ".ssh" / "config"; files = [config]
    config_dir = home / ".ssh" / "config.d"
    if config_dir.is_dir(): files += sorted(config_dir.glob("*"))
    hosts = []; current = None; includes = []
    for path in files:
        if not path.is_file(): continue
        if exclude_managed and path.name.startswith("50-netbot.conf"): continue
        for raw in path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"): continue
            parts = line.split(None, 1)
            if len(parts) != 2: continue
            key, value = parts
            if key.lower() == "include": includes.append({"path": value, "source": str(path)})
            elif key.lower() == "host":
                if "*" not in value and "?" not in value: current = SSHHost(value, source=str(path)); hosts.append(current)
                else: current = None
            elif current:
                low = key.lower()
                if low == "hostname": current.hostname = value
                elif low == "user": current.user = value
                elif low == "port":
                    try: current.port = int(value)
                    except ValueError: pass
                elif low == "identityfile": current.identity_files.append(value)
    return hosts, includes

def public_key_inventory(home: Path) -> list[dict]:
    result = []
    for path in sorted((home / ".ssh").glob("*.pub")):
        try:
            out = subprocess.run(["ssh-keygen", "-E", "sha256", "-lf", str(path)], text=True, capture_output=True, check=True).stdout.strip()
            m = re.match(r"\S+\s+(\S+)\s+\S+\s*(.*)", out)
            result.append({"path": str(path), "fingerprint": m.group(1) if m else out, "comment": m.group(2) if m else ""})
        except (OSError, subprocess.CalledProcessError): pass
    return result

def classify_aliases(hosts, nodes):
    by_name = {x.name: x for x in nodes if x.name}
    by_dns = {x.dns_name.rstrip("."): x for x in nodes if x.dns_name}
    addresses = {ip: x for x in nodes for ip in x.addresses}
    result = []
    for host in hosts:
        target = (host.hostname or host.alias).rstrip(".")
        node = by_name.get(target) or by_dns.get(target) or addresses.get(target)
        if target in {"127.0.0.1", "::1", "localhost"} or host.port not in (None, 22):
            classification = "local-forwarded-or-child"
            source = "SSH target/port"
        elif node:
            classification = "tailscale-node"
            source = "Tailscale name/DNS/IP"
        elif target == host.alias:
            classification = "local-DNS-or-unknown"
            source = "SSH alias only"
        else:
            classification = "unknown"
            source = "SSH target only"
        result.append({"alias": host.alias, "target": host.hostname or host.alias, "user": host.user,
                       "port": host.port or 22, "classification": classification, "source": source,
                       "tailscale_name": node.name if node else None, "tailscale_node_id": node.node_id if node else None})
    return result

def effective_config(alias, runner=subprocess.run):
    try:
        completed = runner(["ssh", "-G", alias], text=True, capture_output=True, check=False)
    except OSError as exc:
        return {"alias": alias, "status": "observer/tool-unavailable", "error": str(exc)}
    if completed.returncode != 0:
        return {"alias": alias, "status": "unknown", "error": (completed.stderr or "ssh -G failed").strip()}
    wanted = {"hostname", "user", "port", "identityfile", "proxyjump", "proxycommand", "canonicalizehostname", "canonicalizemaxdots"}
    values = {}
    for line in completed.stdout.splitlines():
        parts=line.split(None, 1)
        if not parts or parts[0].lower() not in wanted: continue
        key=parts[0].lower(); value=parts[1].strip() if len(parts)>1 else ""
        if key == "identityfile": values.setdefault(key, []).append(value)
        else: values[key]=value
    return {"alias":alias,"status":"available","effective":values}

def probe_ssh(alias, runner=subprocess.run, timeout=4):
    # An alias is already a complete OpenSSH target. In particular, do not
    # append -p 22 here: that would override a manual Port such as mikoshi's
    # local-forwarded 2222 and could produce a misleading host-key result.
    command=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=3","-o","ConnectionAttempts=1",alias,"true"]
    try:
        completed=runner(command,text=True,capture_output=True,check=False,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"target":alias,"status":"timeout/unreachable","detail":str(exc)}
    except OSError as exc:
        return {"target":alias,"status":"observer/tool-unavailable","detail":str(exc)}
    error=(completed.stderr or "").strip(); low=error.lower()
    if completed.returncode == 0: status="reachable-authenticated"
    elif "host key verification failed" in low or "remote host identification" in low: status="host-key-verification-problem"
    elif "permission denied" in low or "authentication" in low: status="network-reachable-authentication-failed"
    elif "connection refused" in low: status="connection-refused"
    elif "could not resolve hostname" in low or "name or service not known" in low or "nodename nor servname" in low: status="name-resolution-failure"
    elif "timed out" in low or "operation timed out" in low: status="timeout/unreachable"
    else: status="unknown-error"
    return {"target":alias,"status":status,"returncode":completed.returncode,"detail":error}

def probe_endpoint(host, user=None, port=22, runner=subprocess.run, timeout=4):
    target=f"{user}@{host}" if user else host
    command=["ssh","-o","BatchMode=yes","-o","ConnectTimeout=3","-o","ConnectionAttempts=1","-p",str(port),target,"true"]
    try:
        completed=runner(command,text=True,capture_output=True,check=False,timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return {"target":target,"status":"timeout/unreachable","detail":str(exc)}
    except OSError as exc:
        return {"target":target,"status":"observer/tool-unavailable","detail":str(exc)}
    error=(completed.stderr or "").strip(); low=error.lower()
    if completed.returncode == 0: status="reachable-authenticated"
    elif "host key verification failed" in low or "remote host identification" in low: status="host-key-verification-problem"
    elif "permission denied" in low or "authentication" in low: status="network-reachable-authentication-failed"
    elif "connection refused" in low: status="connection-refused"
    elif "could not resolve hostname" in low or "name or service not known" in low or "nodename nor servname" in low: status="name-resolution-failure"
    elif "timed out" in low or "operation timed out" in low: status="timeout/unreachable"
    else: status="unknown-error"
    return {"target":target,"status":status,"returncode":completed.returncode,"detail":error}

def known_host_fingerprints(home: Path, runner=subprocess.run):
    known_hosts=home / ".ssh" / "known_hosts"
    if not known_hosts.is_file(): return {"status":"unknown","entries":[]}
    try:
        completed=runner(["ssh-keygen","-lf",str(known_hosts)],text=True,capture_output=True,check=False)
    except OSError as exc:
        return {"status":"observer/tool-unavailable","error":str(exc),"entries":[]}
    if completed.returncode != 0:
        return {"status":"unknown","error":(completed.stderr or "ssh-keygen failed").strip(),"entries":[]}
    entries=[]
    for line in completed.stdout.splitlines():
        parts=line.split()
        if len(parts) < 4: continue
        key_type=parts[-1].strip("()")
        entries.append({"host":parts[2],"fingerprint":parts[1],"key_type":key_type,"source":"local known_hosts","trust":"known/trusted locally"})
    return {"status":"available","entries":entries}
