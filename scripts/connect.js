require("dotenv").config();
const { spawn } = require("child_process");

const sshPrivateKeyPath = process.env.SSH_PRIVATE_KEY_PATH;
const sshUser = process.env.SSH_USER;
const sshHost = process.env.SSH_HOST;

if (!sshPrivateKeyPath || !sshUser || !sshHost) {
  console.error("SSH_PRIVATE_KEY_PATH, SSH_USER, and SSH_HOST are required");
  process.exit(1);
}

const sshCommand = [
  "-i",
  sshPrivateKeyPath,
  "-p",
  "22",
  `${sshUser}@${sshHost}`,
];

console.log(`Connecting to bastion host...`);

const sshProcess = spawn("ssh", sshCommand, { stdio: "inherit" });

sshProcess.on("close", (code) => {
  console.log(`SSH process exited with code ${code}`);
  if (code !== 0 && code !== null) {
    process.exitCode = code;
  }
});
