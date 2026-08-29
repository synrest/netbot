import os, shutil, subprocess, tempfile
from pathlib import Path
from .discovery.ssh import inspect_ssh
from .generate.ssh import plan as ssh_plan, render_installed

INCLUDE="Include ~/.ssh/config.d/50-netbot.conf"
RELEVANT=("hostname","user","port","identityfile","proxyjump","proxycommand","identitiesonly","canonicalizehostname","canonicalizemaxdots")

def _effective(alias, config, home, runner=subprocess.run):
    env=os.environ.copy(); env["HOME"]=str(home)
    try: result=runner(["ssh","-G","-F",str(config),alias],text=True,capture_output=True,check=False,env=env)
    except OSError as exc: return {"status":"tool-unavailable","error":str(exc)}
    if result.returncode: return {"status":"invalid","error":(result.stderr or "ssh -G failed").strip()}
    values={}
    for line in result.stdout.splitlines():
        parts=line.split(None,1); key=parts[0].lower() if parts else ""
        if key not in RELEVANT: continue
        value=parts[1].strip() if len(parts)>1 else ""
        if key=="identityfile": values.setdefault(key,[]).append(value)
        else: values[key]=value
    return {"status":"available","values":values}

def _aliases(home): return [host.alias for host in inspect_ssh(home)[0]]

def _candidate(home, config, installed_text, aliases):
    with tempfile.TemporaryDirectory(prefix="netbot-ssh-preflight-") as temp:
        root=Path(temp); sshdir=root/".ssh"; (sshdir/"config.d").mkdir(parents=True)
        candidate=sshdir/"config"; candidate.write_bytes(config.read_bytes() if config.exists() else b"")
        (sshdir/"config.d"/"50-netbot.conf").write_text(installed_text)
        candidate.write_text(_with_top_level_include(candidate.read_text()))
        before={a:_effective(a,config,home) for a in aliases}; after={a:_effective(a,candidate,root) for a in aliases}
        return before,after

def _with_top_level_include(original):
    lines=original.splitlines(True); lines=[line for line in lines if line.strip()!=INCLUDE]
    index=next((i for i,line in enumerate(lines) if line.strip().lower().startswith(("host ","match "))),len(lines))
    lines.insert(index,INCLUDE+"\n")
    return "".join(lines)

def _include_is_top_level(config):
    if not config.exists(): return False
    lines=config.read_text(errors="replace").splitlines()
    first_host=next((i for i,line in enumerate(lines) if line.strip().lower().startswith(("host ","match "))),len(lines))
    return any(line.strip()==INCLUDE for line in lines[:first_host])

def build_plan(result, home):
    items=ssh_plan(result)
    config=home/".ssh"/"config"; config_dir=home/".ssh"/"config.d"; installed=config_dir/"50-netbot.conf"
    installed_text=render_installed(items)
    aliases=_aliases(home); generated_aliases=[x["entry"]["alias"] for x in items if x.get("entry")]
    before,preflight_after=_candidate(home,config,installed_text,sorted(set(aliases+generated_aliases)))
    include_present=_include_is_top_level(config)
    return {"items":items,"installed_text":installed_text,"config":config,"config_dir":config_dir,"installed":installed,"aliases":aliases,"include_present":include_present,"before":before,"preflight_after":preflight_after,"candidate_valid":all(x.get("status")=="available" for x in preflight_after.values()),"needs_dir":not config_dir.exists(),"needs_file":not installed.exists(),"file_changed":(not installed.exists() or installed.read_text(errors="replace")!=installed_text),"needs_include":not include_present}

def dry_run(plan):
    return {"directories_created":[str(plan["config_dir"])] if plan["needs_dir"] else [],"files_created":[str(plan["installed"])] if plan["needs_file"] else [],"files_modified":[str(plan["installed"])] if plan["file_changed"] and not plan["needs_file"] else [],"include_proposed":INCLUDE if plan["needs_include"] else "already present","backup_plan":"backup existing config and managed file before write; rollback on invariant failure","regression_aliases":plan["aliases"],"candidate_valid":plan["candidate_valid"]}

def _atomic_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True,exist_ok=True); temp=path.with_name(path.name+".netbot-tmp")
    temp.write_text(text); os.chmod(temp,mode); os.replace(temp,path)

def apply(plan):
    if not plan["candidate_valid"]: raise RuntimeError("candidate SSH configuration failed preflight")
    if not plan["needs_dir"] and not plan["file_changed"] and not plan["needs_include"]:
        return {"status":"success","backups":[],"aliases_changed":0,"include_active":True,"idempotent":True}
    backups=[]; config=plan["config"]; installed=plan["installed"]
    if config.exists():
        backup=config.with_name(config.name+".netbot-backup"); shutil.copy2(config,backup); backups.append(backup)
    if installed.exists():
        backup=installed.with_name(installed.name+".netbot-backup"); shutil.copy2(installed,backup); backups.append(backup)
    try:
        _atomic_write(installed,plan["installed_text"])
        if plan["needs_include"]:
            original=config.read_text() if config.exists() else ""
            _atomic_write(config,_with_top_level_include(original),0o600)
        after={a:_effective(a,config,config.parent.parent) for a in plan["aliases"]}
        if any(after[a].get("values")!=plan["before"][a].get("values") for a in plan["aliases"]): raise RuntimeError("effective SSH behavior changed; rolling back")
        for item in plan["items"]:
            if item.get("entry"):
                values=_effective(item["entry"]["alias"],config,config.parent.parent).get("values",{})
                entry=item["entry"]
                if values.get("hostname")!=entry["hostname"] or values.get("user")!=entry["user"] or values.get("port")!=str(entry["port"]): raise RuntimeError("generated SSH alias did not obtain its intended effective values; rolling back")
                if entry.get("identityfile") and values.get("identityfile")!=entry["identityfile"]: raise RuntimeError("generated SSH alias did not obtain its intended identity file; rolling back")
        return {"status":"success","backups":[str(x) for x in backups],"aliases_changed":0,"include_active":True}
    except Exception:
        if backups:
            for backup in backups:
                target=backup.with_name(backup.name.replace(".netbot-backup","")); shutil.copy2(backup,target)
        if plan["needs_file"] and installed.exists(): installed.unlink()
        if plan["needs_dir"] and plan["config_dir"].exists() and not any(plan["config_dir"].iterdir()): plan["config_dir"].rmdir()
        raise

def drift(plan):
    installed=plan["installed"]
    return {"installed":str(installed),"active":plan["include_present"],"drift":(not installed.exists()) or installed.read_text(errors="replace")!=plan["installed_text"]}
