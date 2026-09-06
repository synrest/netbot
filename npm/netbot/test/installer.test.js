const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const {safeVersion, sha256, install, stableLauncher} = require('../lib/installer');

test('rejects unsafe version paths', () => assert.throws(() => safeVersion('../tmp'), /invalid/));
test('uses absolute stable launcher target', () => assert.match(stableLauncher('/tmp/netbot', '/tmp/python'), /\/tmp\/netbot\/current\/venv\/bin\/python/));
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
