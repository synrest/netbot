import json, tempfile, unittest
from pathlib import Path
from netbot.discovery.tailscale import normalize_status
from netbot.config import load_topology
from netbot.reconcile import reconcile, generate
from netbot.reconcile import identity_match
from netbot.models import DesiredHost, TailscaleNode
from netbot.generate.ssh import plan as make_ssh_plan, render as render_ssh_plan
from netbot.activation import build_plan, dry_run as activation_dry_run, apply as activation_apply, drift as activation_drift
from netbot.migration import _replace_host_blocks
from netbot.discovery.ssh import inspect_ssh, classify_aliases, effective_config, probe_ssh, known_host_fingerprints
from netbot.discovery.agent import parse_agent_observation, observe_agent
from netbot.config import load_agent_settings
from netbot.authority import host_capabilities, authority_for_operation
from netbot.agent import version_state, update_plan

def fixture():
    return {"Self":{"ID":"self","HostName":"arasaka","DNSName":"arasaka.tail","TailscaleIPs":["100.1.1.1"],"Online":True},"Peer":{"n1":{"ID":"n1","HostName":"orion","DNSName":"orion.tail","TailscaleIPs":["100.1.1.2"],"Online":True},"n2":{"ID":"n2","HostName":"mystery","Online":False}}}

class NetbotTests(unittest.TestCase):
  def test_enroll_is_informational_only(self):
    from contextlib import redirect_stdout
    from io import StringIO
    from netbot.cli import main
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); output=StringIO()
      with redirect_stdout(output): main(["enroll"])
      text=output.getvalue()
      self.assertIn("sudo tailscale up --ssh --advertise-tags=tag:netbot-bootstrap", text)
      self.assertIn("sudo tailscale up --ssh", text)
      self.assertIn("sudo tailscale set --ssh", text)
      self.assertFalse((root/"state.sqlite3").exists())

  def test_parse_and_match(self):
    nodes=normalize_status(fixture()); self.assertEqual([x.name for x in nodes],["arasaka","orion","mystery"])

  def test_reconcile_fresh_db_and_generate(self):
    with tempfile.TemporaryDirectory() as d:
      tmp_path=Path(d); cfg=tmp_path/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  arasaka:\n    class: core\n  orion:\n    class: satellite\n  mikoshi:\n    class: core\n")
      import netbot.reconcile as reconcile_module
      old=reconcile_module.discover; reconcile_module.discover=lambda: (normalize_status(fixture()),None)
      try:
        home=tmp_path/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("Host orion\n  HostName orion\n  User zero\n")
        db=tmp_path/"state.sqlite3"; r1=reconcile(cfg,db,home); r2=reconcile(cfg,db,home)
        self.assertEqual(len(r1["unknown"]),1); self.assertTrue(any(x["kind"]=="expected_absent" for x in r1["changes"]))
        self.assertEqual(r1["summary"],r2["summary"]); self.assertEqual(r2["events"],[]); self.assertEqual(r2["changes"],r1["changes"])
        out=tmp_path/"topology.json"; generate(r2,out); data=json.loads(out.read_text()); self.assertEqual(data["hosts"][0]["identity"],"arasaka")
      finally: reconcile_module.discover=old

  def test_observer_unavailable_is_not_absent(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); cfg=root/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  orion:\n    class: satellite\n")
      import netbot.reconcile as reconcile_module
      old=reconcile_module.discover; reconcile_module.discover=lambda: ([],"socket unavailable")
      try:
        home=root/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("")
        r=reconcile(cfg,root/"state.sqlite3",home)
        self.assertEqual(r["rows"][0]["status"],"observer-unavailable"); self.assertEqual(r["changes"],[]); self.assertEqual(r["summary"]["absent"],0)
      finally: reconcile_module.discover=old

  def test_ambiguous_identity_is_not_guessed(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); cfg=root/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  orion:\n    class: satellite\n  kiroshi:\n    class: core\n")
      import netbot.reconcile as reconcile_module
      old=reconcile_module.discover; reconcile_module.discover=lambda: (normalize_status({"Peer":{"x":{"ID":"x","HostName":"orion","DNSName":"kiroshi.tail","Online":True}}}),None)
      try:
        home=root/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("")
        r=reconcile(cfg,root/"state.sqlite3",home)
        self.assertIsNone(r["rows"][0]["identity"]); self.assertEqual(r["rows"][0]["mapping_status"],"ambiguous")
      finally: reconcile_module.discover=old

  def test_ssh_alias_classification(self):
    with tempfile.TemporaryDirectory() as d:
      home=Path(d); (home/".ssh").mkdir(); (home/".ssh"/"config").write_text("Host mikoshi\n  HostName 127.0.0.1\n  Port 2222\n  User zero\nHost kiroshi\n  HostName 100.100.57.74\n  User rafael\n")
      hosts,_=inspect_ssh(home); nodes=normalize_status({"Peer":{"x":{"ID":"x","HostName":"kiroshi","TailscaleIPs":["100.100.57.74"]}}}); aliases=classify_aliases(hosts,nodes)
      self.assertEqual(aliases[0]["classification"],"local-forwarded-or-child"); self.assertEqual(aliases[1]["classification"],"tailscale-node")

  def test_observer_recovery_changes_unknown_to_present(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); cfg=root/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  orion:\n    class: satellite\n")
      import netbot.reconcile as reconcile_module
      old=reconcile_module.discover; home=root/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("")
      try:
        reconcile_module.discover=lambda: ([],"socket unavailable")
        unavailable=reconcile(cfg,root/"state.sqlite3",home)
        reconcile_module.discover=lambda: (normalize_status({"Peer":{"x":{"NodeID":42,"HostName":"orion","Online":True}}}),None)
        recovered=reconcile(cfg,root/"state.sqlite3",home)
        self.assertEqual(unavailable["summary"]["observer_unavailable"],1); self.assertEqual(recovered["rows"][0]["status"],"present")
        self.assertEqual(recovered["rows"][0]["node_id"],"42"); self.assertTrue(recovered["events"])
      finally: reconcile_module.discover=old

  def test_effective_config_normalization(self):
    class Completed:
      returncode=0; stderr=""; stdout="hostname 100.0.0.1\nuser rafael\nport 22\nidentityfile ~/.ssh/id_ed25519\nproxyjump none\n"
    observed=effective_config("kiroshi",runner=lambda *args,**kwargs: Completed())
    self.assertEqual(observed["effective"]["hostname"],"100.0.0.1"); self.assertEqual(observed["effective"]["identityfile"],["~/.ssh/id_ed25519"])

  def test_probe_result_categories(self):
    class Completed:
      def __init__(self,code,error): self.returncode=code; self.stderr=error; self.stdout=""
    cases=[
      (Completed(0,""),"reachable-authenticated"),
      (Completed(255,"Permission denied (publickey)."),"network-reachable-authentication-failed"),
      (Completed(255,"Connection refused"),"connection-refused"),
      (Completed(255,"ssh: connect to host x port 22: Operation timed out"),"timeout/unreachable"),
      (Completed(255,"Host key verification failed."),"host-key-verification-problem"),
    ]
    for completed,expected in cases:
      result=probe_ssh("alias",runner=lambda *args,completed=completed,**kwargs: completed)
      self.assertEqual(result["status"],expected)
    timeout=probe_ssh("alias",runner=lambda *args,**kwargs: (_ for _ in ()).throw(__import__('subprocess').TimeoutExpired("ssh",4)))
    self.assertEqual(timeout["status"],"timeout/unreachable")

  def test_alias_probe_does_not_override_manual_port(self):
    captured=[]
    class Completed:
      returncode=0; stderr=""; stdout=""
    result=probe_ssh("mikoshi",runner=lambda command,**kwargs: (captured.append(command) or Completed()))
    self.assertEqual(result["status"],"reachable-authenticated")
    self.assertNotIn("-p", captured[0])
    self.assertEqual(captured[0][-2:], ["mikoshi", "true"])

  def test_multiple_access_paths_and_offline_node(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); cfg=root/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  oracle:\n    class: unknown\n")
      import netbot.reconcile as reconcile_module
      old=reconcile_module.discover; reconcile_module.discover=lambda: (normalize_status({"Peer":{"x":{"NodeID":7,"HostName":"oracle","DNSName":"oracle.tail","TailscaleIPs":["100.72.113.101"],"Online":False}}}),None)
      try:
        home=root/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("Host oracle\n  HostName 100.72.113.101\n  User rafael\n")
        r=reconcile(cfg,root/"state.sqlite3",home); paths=r["access_paths"]
        self.assertEqual({p["kind"] for p in paths},{"ssh","tailscale"}); self.assertEqual([p for p in paths if p["kind"]=="tailscale"][0]["result"],"unknown")
      finally: reconcile_module.discover=old

  def test_known_host_fingerprints_are_metadata_only(self):
    with tempfile.TemporaryDirectory() as d:
      home=Path(d); (home/".ssh").mkdir(); (home/".ssh"/"known_hosts").write_text("placeholder")
      class Completed:
        returncode=0; stderr=""; stdout="256 SHA256:abc host (ED25519)\n"
      result=known_host_fingerprints(home,runner=lambda *args,**kwargs: Completed())
      self.assertEqual(result["entries"],[{"host":"host","fingerprint":"SHA256:abc","key_type":"ED25519","source":"local known_hosts","trust":"known/trusted locally"}])

  def test_access_observation_is_idempotent(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); cfg=root/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  oracle:\n    class: unknown\n")
      import netbot.reconcile as reconcile_module, sqlite3
      old=reconcile_module.discover; reconcile_module.discover=lambda: (normalize_status({"Peer":{"x":{"NodeID":7,"HostName":"oracle","Online":False}}}),None)
      try:
        home=root/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("Host oracle\n  HostName 100.72.113.101\n")
        db=root/"state.sqlite3"; reconcile(cfg,db,home); reconcile(cfg,db,home)
        connection=sqlite3.connect(db)
        try: self.assertEqual(connection.execute("select count(*) from access_observations").fetchone()[0],2)
        finally: connection.close()
      finally: reconcile_module.discover=old

  def test_explicit_node_id_survives_hostname_drift(self):
    desired=DesiredHost("kiroshi",{"bindings":{"tailscale":{"node_id":"7","name":"kiroshi"}}})
    result=identity_match(desired,TailscaleNode("7","new-name","new-name.tail",[],True,"Linux",None))
    self.assertEqual(result[:3],("explicit","topology.tailscale.node_id","hostname-drift"))

  def test_explicit_binding_conflict_is_not_remapped(self):
    desired=DesiredHost("kiroshi",{"bindings":{"tailscale":{"node_id":"7","name":"kiroshi"}}})
    result=identity_match(desired,TailscaleNode("8","kiroshi","kiroshi.tail",[],True,"Linux",None))
    self.assertEqual(result[2],"conflict")

  def test_preview_is_deterministic_and_has_no_speculation(self):
    items=[{"identity":"orion","manual":"unknown","proposal":"none","action":"none","reason":"no observed SSH alias"}]
    self.assertEqual(render_ssh_plan(items),render_ssh_plan(items)); self.assertNotIn("Host orion",render_ssh_plan(items)); self.assertIn("PREVIEW ONLY",render_ssh_plan(items))

  def test_hostname_change_becomes_migration_candidate_not_reassignment(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); cfg=root/"topology.yaml"; cfg.write_text("version: 1\nhosts:\n  lourdes:\n    class: unknown\n    bindings:\n      tailscale:\n        node_id: 7\n        name: lourdes\n  orion:\n    class: satellite\n")
      import netbot.reconcile as reconcile_module
      old=reconcile_module.discover; reconcile_module.discover=lambda: (normalize_status({"Peer":{"x":{"NodeID":7,"HostName":"orion","DNSName":"orion.tail","Online":True}}}),None)
      try:
        home=root/"home"; (home/".ssh").mkdir(parents=True); (home/".ssh"/"config").write_text("")
        result=reconcile(cfg,root/"state.sqlite3",home)
        self.assertEqual(result["rows"][0]["identity"],"lourdes"); self.assertTrue(result["rows"][0]["hostname_drift"])
        self.assertEqual(next(x for x in result["rows"] if x["identity"]=="orion")["status"],"unbound")
        self.assertEqual(result["migration_candidates"][0]["from_identity"],"lourdes")
      finally: reconcile_module.discover=old

  def test_migration_rewrite_transfers_binding_and_preserves_lineage(self):
    original="version: 1\nhosts:\n  lourdes:\n    class: unknown\n    bindings:\n      tailscale:\n        node_id: \"7\"\n        name: lourdes\n  orion:\n    class: satellite\n"
    updated=_replace_host_blocks(original,"lourdes","orion","7","lourdes")
    self.assertIn("lifecycle: retired",updated); self.assertIn("superseded_by: orion",updated)
    self.assertEqual(updated.count('node_id: "7"'),1); self.assertIn("name: orion",updated); self.assertIn("- orion",updated); self.assertIn("user: lourdes",updated)

  def activation_result(self, root):
    return {"desired":[DesiredHost("kiroshi",{})],"access_paths":[],"rows":[],"ssh_aliases":[]}

  def test_activation_dry_run_writes_nothing(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); (root/".ssh").mkdir(); (root/".ssh"/"config").write_text("Host kiroshi\n  HostName 100.100.57.74\n  User rafael\n")
      plan=build_plan(self.activation_result(root),root); result=activation_dry_run(plan)
      self.assertTrue(result["candidate_valid"]); self.assertFalse((root/".ssh"/"config.d").exists()); self.assertFalse((root/".ssh"/"config").read_text().endswith("50-netbot.conf\n"))

  def test_activation_apply_idempotence_and_drift(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); (root/".ssh").mkdir(); config=root/".ssh"/"config"; config.write_text("Host kiroshi\n  HostName 100.100.57.74\n  User rafael\n")
      first=build_plan(self.activation_result(root),root); result=activation_apply(first); self.assertEqual(result["aliases_changed"],0); before=config.read_text(); installed=root/".ssh"/"config.d"/"50-netbot.conf"; self.assertTrue(installed.exists())
      second=build_plan(self.activation_result(root),root); self.assertFalse(second["needs_include"]); self.assertFalse(second["file_changed"]); self.assertFalse(activation_dry_run(second)["files_modified"]); self.assertFalse(activation_drift(second)["drift"])
      installed.write_text(installed.read_text()+"# manual drift\n"); self.assertTrue(activation_drift(build_plan(self.activation_result(root),root))["drift"]); self.assertEqual(config.read_text(),before)

  def test_activation_rolls_back_on_effective_change(self):
    with tempfile.TemporaryDirectory() as d:
      root=Path(d); (root/".ssh").mkdir(); config=root/".ssh"/"config"; original="Host kiroshi\n  HostName 100.100.57.74\n"; config.write_text(original)
      plan=build_plan(self.activation_result(root),root)
      import netbot.activation as activation
      old=activation._effective; activation._effective=lambda *args,**kwargs: {"status":"available","values":{"hostname":"changed"}}
      try:
        with self.assertRaises(RuntimeError): activation_apply(plan)
        self.assertEqual(config.read_text(),original); self.assertFalse((root/".ssh"/"config.d"/"50-netbot.conf").exists())
      finally: activation._effective=old

  def test_agent_privileged_unbounded_observation(self):
    output="""NETBOT_AGENT installed=yes
NETBOT_AGENT lifecycle_markers=no
NETBOT_AGENT timer=absent
NETBOT_AGENT sudo_begin
User lourdes may run the following commands on orion:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
NETBOT_AGENT sudo_end
NETBOT_AGENT sudo_rc=0
"""
    result=parse_agent_observation(output)
    self.assertEqual(result["privilege_state"],"privileged")
    self.assertEqual(result["user"],"lourdes")
    self.assertEqual(result["risk"],"persistent-unbounded-privilege")
    self.assertEqual(result["expiry"],"none-observed")
    self.assertEqual(result["reboot_persistence"],"yes")

  def test_agent_installed_inactive_and_absent(self):
    inactive=parse_agent_observation("""NETBOT_AGENT installed=yes
NETBOT_AGENT lifecycle_markers=no
NETBOT_AGENT timer=absent
NETBOT_AGENT sudo_begin
User lourdes may run the following commands on orion:
sudo: a password is required
NETBOT_AGENT sudo_end
NETBOT_AGENT sudo_rc=1
""")
    absent=parse_agent_observation("NETBOT_AGENT installed=no\nNETBOT_AGENT sudo_begin\nNETBOT_AGENT sudo_end\nNETBOT_AGENT sudo_rc=0\n")
    self.assertEqual(inactive["privilege_state"],"installed-inactive")
    self.assertEqual(absent["installed"],"no")
    self.assertEqual(absent["privilege_state"],"unknown")

  def test_agent_observer_lacks_sudo_permission(self):
    result=parse_agent_observation("""NETBOT_AGENT installed=yes
NETBOT_AGENT sudo_begin
lourdes is not in the sudoers file.  This incident will be reported.
NETBOT_AGENT sudo_end
NETBOT_AGENT sudo_rc=1
""")
    self.assertEqual(result["privilege_state"],"unknown")

  def test_agent_sudoers_file_alone_is_not_effective(self):
    result=parse_agent_observation("""NETBOT_AGENT installed=yes
NETBOT_AGENT lifecycle_markers=no
NETBOT_AGENT timer=absent
NETBOT_AGENT sudo_begin
User lourdes may run the following commands on orion:
    (ALL) /usr/bin/id
NETBOT_AGENT sudo_end
NETBOT_AGENT sudo_rc=0
""")
    self.assertNotEqual(result["privilege_state"],"privileged")

  def test_agent_observer_unavailable(self):
    result=parse_agent_observation("",returncode=255,error="connection refused")
    self.assertEqual(result["status"],"observer-unavailable")
    self.assertEqual(result["privilege_state"],"unknown")

  def test_agent_ignores_misleading_unprivileged_status_text(self):
    output="""Temporary agent sudo access is disabled.
NETBOT_AGENT installed=yes
NETBOT_AGENT lifecycle_markers=no
NETBOT_AGENT timer=absent
NETBOT_AGENT sudo_begin
User lourdes may run the following commands on orion:
    (ALL) NOPASSWD: ALL
NETBOT_AGENT sudo_end
NETBOT_AGENT sudo_rc=0
"""
    self.assertEqual(parse_agent_observation(output)["privilege_state"],"privileged")

  def test_agent_observation_runner_is_read_only_probe(self):
    class Completed:
      returncode=0; stderr=""; stdout="NETBOT_AGENT installed=no\nNETBOT_AGENT sudo_begin\nNETBOT_AGENT sudo_end\nNETBOT_AGENT sudo_rc=0\n"
    captured=[]
    result=observe_agent("orion",runner=lambda command,**kwargs: (captured.append(command) or Completed()))
    self.assertEqual(result["installed"],"no")
    self.assertNotIn("agent-temporary status", " ".join(captured[0]))
    self.assertIn("sudo -n -l", captured[0][-1])

  def test_agent_observation_is_idempotent(self):
    import sqlite3
    from netbot.state import State
    with tempfile.TemporaryDirectory() as d:
      state=State(Path(d)/"state.sqlite3")
      observation={"status":"available","installed":"yes","privilege_state":"privileged","risk":"persistent-unbounded-privilege"}
      state.agent_observation("now","orion",observation); state.agent_observation("later","orion",observation); state.close()
      db=sqlite3.connect(Path(d)/"state.sqlite3")
      self.assertEqual(db.execute("select count(*) from agent_observations").fetchone()[0],1)
      db.close()

  def test_authority_levels_and_capabilities(self):
    self.assertEqual(authority_for_operation("agent-status"),"observe")
    inactive={"status":"available","privilege_state":"installed-inactive"}
    active={"status":"available","privilege_state":"privileged"}
    self.assertEqual(host_capabilities(inactive,True)["maintain"],"blocked")
    self.assertEqual(host_capabilities(active,True)["maintain"],"available")
    self.assertEqual(host_capabilities(None,None)["observe"],"unavailable")

  def test_agent_desired_version_states(self):
    current={"status":"available","installed":"yes","version":"0.3.0","platform":"linux-systemd"}
    self.assertEqual(version_state("0.3.0",current),"current")
    self.assertEqual(version_state("0.4.0",current),"update-needed")
    self.assertEqual(version_state("0.2.0",current),"newer-than-desired")
    self.assertEqual(version_state("0.3.0",{"status":"available","installed":"yes","platform":"linux-systemd"}),"unknown")
    self.assertEqual(version_state("0.3.0",{"status":"available","installed":"yes","version":"0.3.0","platform":"unsupported"}),"unsupported")

  def test_agent_update_plan_blocks_inactive_maintenance(self):
    observation={"status":"available","installed":"yes","version":"0.2.0","platform":"linux-systemd","privilege_state":"installed-inactive"}
    plan=update_plan("orion","0.3.0",observation,ssh_observed=True)
    self.assertTrue(plan["dry_run"]); self.assertFalse(plan["maintenance_authorized"])
    self.assertEqual(plan["authority"]["maintain"],"blocked")
    self.assertEqual(plan["stages"][2]["authority"],"maintain")

  def test_agent_update_plan_allows_observed_active_maintenance(self):
    observation={"status":"available","installed":"yes","version":"0.2.0","platform":"linux-systemd","privilege_state":"privileged"}
    plan=update_plan("orion","0.3.0",observation,ssh_observed=True)
    self.assertTrue(plan["maintenance_authorized"])

  def test_agent_settings_are_separate_from_hosts(self):
    with tempfile.TemporaryDirectory() as d:
      path=Path(d)/"topology.yaml"
      path.write_text('version: 1\nagents:\n  temporary:\n    desired_version: "0.3.0"\nhosts:\n  orion:\n    class: satellite\n')
      self.assertEqual(load_agent_settings(path)["temporary_desired_version"],"0.3.0")
      self.assertEqual([h.identity for h in load_topology(path)[1]],["orion"])

if __name__ == "__main__": unittest.main()
