#!/usr/bin/env node
const cp = require('child_process');
const os = require('os');
const path = require('path');

const root = process.env.NETBOT_PREFIX || (process.platform === 'darwin'
  ? path.join(os.homedir(), 'Library', 'Application Support', 'Netbot')
  : path.join(process.env.XDG_DATA_HOME || path.join(os.homedir(), '.local', 'share'), 'netbot'));
const python = path.join(root, 'current', 'venv', 'bin', 'python');
if (!require('fs').existsSync(python)) {
  console.error('Netbot is not installed; install the npm package with a release payload first.');
  process.exit(1);
}
process.env.NETBOT_PREFIX = root;
process.chdir(root);
process.exit(cp.spawnFileSync(python, ['-m', 'netbot.cli', ...process.argv.slice(2)], {stdio: 'inherit'}));
