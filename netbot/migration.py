import os, shutil, socket, subprocess, tempfile
from pathlib import Path
from .config import load_topology
from .reconcile import reconcile, now
from .state import State
from .generate.ssh import plan as ssh_plan, write_preview
from .activation import build_plan, apply as apply_ssh
from .discovery.ssh import probe_ssh

def _replace_host_blocks(text, source, target, node_id, user):
    lines=text.splitlines(True); starts=[i for i,l in enumerate(lines) if l.startswith("  ") and not l.startswith("    ") and l.rstrip().endswith(":")]
    names=[lines[i].strip()[:-1] for i in starts]; source_i=names.index(source); target_i=names.index(target)
    ends=starts[1:]+[len(lines)]
    def block(name,i,end):
        b=lines[starts[i]:end]
        if name==source:
            out=[]; skipping=False
            for line in b:
                if line.startswith("    bindings:"): skipping=True; continue
                if skipping and (line.startswith("    ") or not line.strip()): continue
                skipping=False; out.append(line)
            if not any("lifecycle: retired" in x for x in out): out += ["    lifecycle: retired\n","    superseded_by: orion\n"]
            return out
        if name==target:
            out=b[:]
            if not out or not out[-1].endswith("\n"): out.append("\n")
            out += ["    bindings:\n","      tailscale:\n",f"        node_id: \"{node_id}\"\n","        name: orion\n","      ssh:\n","        aliases:\n","          - orion\n",f"        user: {user}\n","        port: 22\n"]
            return out
        return b
    rebuilt=[]
    for i,name in enumerate(names): rebuilt += block(name,i,ends[i])
    return "".join(rebuilt)

def apply_migration(config, db_path, home, source, target):
    version,desired=load_topology(config); source_host=next((h for h in desired if h.identity==source),None); target_host=next((h for h in desired if h.identity==target),None)
    if not source_host or not target_host: raise RuntimeError("source or target identity missing")
    expected=str(source_host.attrs.get("bindings",{}).get("tailscale",{}).get("node_id",""))
    if not expected: raise RuntimeError("source has no explicit Tailscale node ID binding")
    try: socket.getaddrinfo(target,22)
    except OSError as exc: raise RuntimeError(f"target hostname does not resolve: {target}: {exc}")
    current=reconcile(config,db_path,home,"migrate-preflight")
    source_obs=next((x for x in current["rows"] if x.get("identity")==source and x.get("name")),None)
    if not source_obs or str(source_obs.get("node_id"))!=expected: raise RuntimeError("approved source node ID is not the current live node")
    candidate=next((x for x in current["migration_candidates"] if x["from_identity"]==source and x["to_identity"]==target),None)
    if not candidate or target_host.attrs.get("bindings"): raise RuntimeError("migration precondition failed: target is bound or candidate is absent")
    ssh_alias=next((x for x in current["ssh_aliases"] if x["alias"]==source),None); user=(ssh_alias or {}).get("user") or "lourdes"
    backup=config.with_name(config.name+".netbot-migration-backup"); shutil.copy2(config,backup)
    try:
        updated=_replace_host_blocks(config.read_text(),source,target,expected,user)
        fd,tmp=tempfile.mkstemp(prefix=config.name+".netbot-",dir=config.parent); os.close(fd); Path(tmp).write_text(updated); os.chmod(tmp,config.stat().st_mode & 0o777); os.replace(tmp,config)
        after=reconcile(config,db_path,home,"migrate-after-topology")
        plan=build_plan(after,home)
        write_preview(plan["items"],Path("generated/50-netbot.conf"))
        activation=apply_ssh(plan)
        syntax=subprocess.run(["ssh","-G","orion"],text=True,capture_output=True,check=False)
        if syntax.returncode: raise RuntimeError("ssh -G orion failed: "+(syntax.stderr or "").strip())
        probe=probe_ssh("orion")
        state=State(db_path); state.migration(now(),source,target,expected,"human-approved rename/migration"); state.close()
        return {"status":"success","source":source,"target":target,"node_id":expected,"backup":str(backup),"ssh_activation":activation,"ssh_probe":probe,"topology":after,"ssh_plan":plan["items"]}
    except Exception:
        shutil.copy2(backup,config)
        raise
