const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const {safeVersion, sha256, install, stableLauncher, runtimeHealthy} = require('../lib/installer');

test('rejects unsafe version paths', () => assert.throws(() => safeVersion('../tmp'), /invalid/));
test('stable launcher gives an actionable repair message for a broken runtime', () => {
  const launcher = stableLauncher('/tmp/netbot', '/tmp/python', '0.4.6');
  assert.match(launcher, /private Python environment is broken/);
  assert.match(launcher, /npm install -g @synrest\/netbot@0\.4\.6 --force/);
  assert.match(launcher, /NETBOT_PYTHON=\$candidate/);
  assert.match(launcher, /python3\.10/);
  assert.match(launcher, /\/tmp\/netbot\/current\/venv\/bin\/python/);
});
test('broken active runtime is detected without touching user state', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'netbot-runtime-'));
  fs.mkdirSync(path.join(root, 'current', 'venv', 'bin'), {recursive: true});
  fs.symlinkSync('/path/that/does/not/exist', path.join(root, 'current', 'venv', 'bin', 'python'));
  assert.equal(runtimeHealthy(root), false);
  assert.equal(fs.lstatSync(path.join(root, 'current', 'venv', 'bin', 'python')).isSymbolicLink(), true);
});
test('wrong checksum never creates an installation', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'netbot-m10-'));
  const artifact = path.join(root, 'release.tar.gz'); fs.writeFileSync(artifact, 'not-a-release');
  assert.throws(() => install({version: '0.3.0', artifact, sha256: '0'.repeat(64), root: path.join(root, 'app'), launcher: path.join(root, 'bin/netbot')}), /checksum/);
  assert.ok(!fs.existsSync(path.join(root, 'app')));
});
test('dry-run performs no writes', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'netbot-m10-'));
  const artifact = path.join(root, 'release.tar.gz'); fs.writeFileSync(artifact, 'release');
  const result = install({version: '0.3.0', artifact, sha256: sha256(artifact), root: path.join(root, 'app'), launcher: path.join(root, 'bin/netbot'), dryRun: true});
  assert.equal(result.result, 'WOULD_INSTALL'); assert.ok(!fs.existsSync(result.root));
});
test('npm and Python versions are synchronized', () => {
  const npmVersion = require('../package.json').version;
  const pyproject = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'pyproject.toml'), 'utf8');
  assert.match(pyproject, new RegExp(`version = "${npmVersion.replace('.', '\\.')}`));
});
test('npm does not claim the Netbot launcher bin', () => {
  assert.equal(Object.prototype.hasOwnProperty.call(require('../package.json'), 'bin'), false);
});
test('direct bootstrap is release-only and never enables services', () => {
  const script = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'bootstrap.sh'), 'utf8');
  assert.match(script, /netbot-\$VERSION\.zip/);
  assert.match(script, /shasum -a 256/);
  assert.match(script, /install\.sh --no-service/);
  assert.doesNotMatch(script, /git clone|tailscale up|scheduler install/);
});
