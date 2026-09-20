const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');

function safeVersion(version) {
  if (!/^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$/.test(version)) throw new Error('invalid release version');
  return version;
}

function defaultRoot() {
  return process.platform === 'darwin'
    ? path.join(os.homedir(), 'Library', 'Application Support', 'Netbot')
    : path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'netbot');
}

function sha256(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

const MIN_PYTHON = [3, 10];

function pythonCandidates(explicit) {
  if (explicit || process.env.NETBOT_PYTHON) return [explicit || process.env.NETBOT_PYTHON];
  return ['python3', 'python3.14', 'python3.13', 'python3.12', 'python3.11', 'python3.10'];
}

function probePython(python) {
  const result = cp.spawnSync(python, ['-c', 'import sys,venv,ensurepip; print(sys.version_info[:2])'], {encoding: 'utf8'});
  if (result.error || result.status !== 0) return null;
  const match = (result.stdout || '').match(/\((\d+),\s*(\d+)\)/);
  if (!match) return null;
  const version = [Number(match[1]), Number(match[2])];
  return version[0] > MIN_PYTHON[0] || (version[0] === MIN_PYTHON[0] && version[1] >= MIN_PYTHON[1])
    ? version : null;
}

function selectPython(explicit) {
  for (const candidate of pythonCandidates(explicit)) {
    if (probePython(candidate)) return candidate;
  }
  throw new Error('Python >= 3.10 with venv/ensurepip is required; set NETBOT_PYTHON to a supported interpreter');
}

function validatePython(python) {
  if (!probePython(python)) throw new Error('Python >= 3.10 with venv/ensurepip is required');
}

function stableLauncher(root, python, version = 'current') {
  const runtime = path.join(root, 'current', 'venv', 'bin', 'python');
  return `#!/bin/sh
set -eu
export NETBOT_PREFIX=${JSON.stringify(root)}
cd ${JSON.stringify(root)}
PYTHON=${JSON.stringify(runtime)}
if [ ! -x "$PYTHON" ] || ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
  echo "Netbot runtime is unavailable: its private Python environment is broken." >&2
  echo "Repair with:" >&2
  echo "  npm install -g @synrest/netbot@${version} --force" >&2
  for candidate in python3 python3.14 python3.13 python3.12 python3.11 python3.10; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys,venv,ensurepip; sys.exit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
      echo "If multiple Python versions are installed, select one explicitly:" >&2
      echo "  NETBOT_PYTHON=$candidate npm install -g @synrest/netbot@${version} --force" >&2
      break
    fi
  done
  exit 1
fi
exec "$PYTHON" -m netbot.cli "$@"
`;
}

function recognizedLauncher(file) {
  if (!fs.existsSync(file) || fs.lstatSync(file).isSymbolicLink() || !fs.statSync(file).isFile()) return false;
  const text = fs.readFileSync(file, 'utf8');
  return text.includes('NETBOT_PREFIX') && text.includes('current/venv/bin/python');
}

function atomicWrite(file, content) {
  fs.mkdirSync(path.dirname(file), {recursive: true, mode: 0o700});
  if (fs.existsSync(file) && fs.lstatSync(file).isSymbolicLink()) throw new Error('launcher path is a symlink');
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.tmp`);
  fs.writeFileSync(temporary, content, {mode: 0o755});
  fs.renameSync(temporary, file);
}

function currentTarget(current) {
  try { return fs.realpathSync(current); } catch (_) { return null; }
}

function currentLinkTarget(current) {
  try { return fs.realpathSync(current); } catch (_) {
    try { return path.resolve(path.dirname(current), fs.readlinkSync(current)); } catch (_) { return null; }
  }
}

function runtimeHealthy(root) {
  const runtime = path.join(root, 'current', 'venv', 'bin', 'python');
  if (!fs.existsSync(runtime)) return false;
  const result = cp.spawnSync(runtime, ['-c', 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)'], {encoding: 'utf8'});
  return !result.error && result.status === 0;
}

function install(options = {}) {
  const version = safeVersion(options.version);
  const root = path.resolve(options.root || defaultRoot());
  const launcher = path.resolve(options.launcher || path.join(os.homedir(), '.local', 'bin', 'netbot'));
  if (!options.artifact) throw new Error('release artifact is missing');
  const artifact = path.resolve(options.artifact);
  if (!fs.existsSync(artifact) || !fs.statSync(artifact).isFile()) throw new Error('release artifact is missing');
  if (!/^[a-f0-9]{64}$/.test(options.sha256 || '') || sha256(artifact) !== options.sha256) throw new Error('release checksum mismatch');
  if (options.dryRun) return {result: 'WOULD_INSTALL', version, root, launcher};
  const python = selectPython(options.python);
  validatePython(python);
  if (fs.existsSync(launcher) && !recognizedLauncher(launcher)) throw new Error('canonical launcher is foreign or unsafe');
  fs.mkdirSync(path.join(root, 'versions'), {recursive: true, mode: 0o700});
  const staging = fs.mkdtempSync(path.join(path.join(root, 'versions'), '.stage-'));
  try {
    const extract = path.join(__dirname, 'extract.py');
    const extracted = cp.spawnSync(python, [extract, artifact, staging, `netbot-${version}`], {encoding: 'utf8'});
    if (extracted.error || extracted.status !== 0) throw new Error((extracted.stderr || 'unsafe release archive').trim());
    const source = path.join(staging, `netbot-${version}`, 'netbot');
    if (!fs.existsSync(source) || !fs.statSync(source).isDirectory()) throw new Error('release payload has invalid structure');
    const finalDir = path.join(root, 'versions', version);
    const current = path.join(root, 'current');
    const repairing = fs.existsSync(finalDir) && currentLinkTarget(current) === path.resolve(finalDir) && !runtimeHealthy(root);
    if (fs.existsSync(finalDir) && !repairing) throw new Error(`version already installed: ${version}`);
    const venv = path.join(staging, 'venv');
    const made = cp.spawnSync(python, ['-m', 'venv', venv], {encoding: 'utf8'});
    if (made.error || made.status !== 0) throw new Error('private Python runtime creation failed');
    const site = cp.spawnSync(path.join(venv, 'bin', 'python'), ['-c', 'import site; print(site.getsitepackages()[0])'], {encoding: 'utf8'});
    if (site.status !== 0) throw new Error('could not locate Python site-packages');
    fs.cpSync(source, path.join(site.stdout.trim(), 'netbot'), {recursive: true});
    const checked = cp.spawnSync(path.join(venv, 'bin', 'python'), ['-c', 'import netbot.cli,netbot.version; print(netbot.version.__version__)'], {encoding: 'utf8'});
    if (checked.status !== 0 || (checked.stdout || '').trim() !== version) throw new Error('staged Netbot validation failed');
    const backup = repairing ? `${finalDir}.broken-${process.pid}` : null;
    if (backup) fs.renameSync(finalDir, backup);
    fs.renameSync(staging, finalDir);
    const previousLink = currentLinkTarget(current);
    const previous = currentTarget(current);
    const link = `${current}.new-${process.pid}`;
    fs.symlinkSync(finalDir, link);
    fs.renameSync(link, current);
    try {
      atomicWrite(launcher, stableLauncher(root, path.join(finalDir, 'venv', 'bin', 'python'), version));
      const launchCheck = cp.spawnSync(path.join(finalDir, 'venv', 'bin', 'python'), ['-m', 'netbot.cli', '--version'], {encoding: 'utf8', env: {...process.env, NETBOT_PREFIX: root}, cwd: root});
      if (launchCheck.status !== 0 || (launchCheck.stdout || '').trim() !== version) throw new Error('launcher verification failed');
      if (backup) fs.rmSync(backup, {recursive: true, force: true});
    } catch (error) {
      fs.unlinkSync(current);
      if (previousLink) fs.symlinkSync(previousLink, current);
      fs.rmSync(finalDir, {recursive: true, force: true});
      if (backup) fs.renameSync(backup, finalDir);
      throw error;
    }
    return {result: repairing ? 'REPAIRED' : 'INSTALLED', version, root, launcher, previous_version: previous ? path.basename(previous) : null, python};
  } catch (error) {
    if (fs.existsSync(staging)) fs.rmSync(staging, {recursive: true, force: true});
    throw error;
  }
}

module.exports = {install, safeVersion, sha256, recognizedLauncher, stableLauncher, selectPython, runtimeHealthy};
