const fs = require('fs');
const path = require('path');
const {install} = require('./installer');

if (process.env.NETBOT_SKIP_POSTINSTALL === '1') process.exit(0);
const metadata = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'release.json'), 'utf8'));
const artifact = process.env.NETBOT_RELEASE_ARTIFACT;
if (!artifact) {
  console.warn('Netbot npm bootstrap installed; set NETBOT_RELEASE_ARTIFACT and run the controlled installer to install the Python payload.');
  process.exit(0);
}
try {
  const result = install({version: metadata.version, artifact, sha256: process.env.NETBOT_RELEASE_SHA256, root: process.env.NETBOT_INSTALL_ROOT});
  console.log(JSON.stringify(result));
} catch (error) {
  console.error(`Netbot installation failed: ${error.message}`);
  process.exit(1);
}
