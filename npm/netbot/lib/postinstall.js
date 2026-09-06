const fs = require('fs');
const os = require('os');
const path = require('path');
const {install} = require('./installer');

if (process.env.NETBOT_SKIP_POSTINSTALL === '1') process.exit(0);
const metadata = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'release.json'), 'utf8'));
(async () => {
  const artifact = process.env.NETBOT_RELEASE_ARTIFACT;
  const digest = process.env.NETBOT_RELEASE_SHA256 || metadata.sha256;
  let temporary = null;
  try {
    let local = artifact;
    if (!local && metadata.artifact) {
      const response = await fetch(metadata.artifact);
      if (!response.ok) throw new Error(`release download failed: HTTP ${response.status}`);
      temporary = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'netbot-npm-')), `netbot-${metadata.version}.zip`);
      fs.writeFileSync(temporary, Buffer.from(await response.arrayBuffer()));
      local = temporary;
    }
    if (!local) throw new Error('release metadata has no artifact URL');
    const result = install({version: metadata.version, artifact: local, sha256: digest, root: process.env.NETBOT_INSTALL_ROOT});
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(`Netbot installation failed: ${error.message}`);
    process.exitCode = 1;
  } finally {
    if (temporary) fs.rmSync(path.dirname(temporary), {recursive: true, force: true});
  }
})();
