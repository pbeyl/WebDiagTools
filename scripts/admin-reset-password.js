#!/usr/bin/env node

const crypto = require('crypto');
const readline = require('readline');
const ACTOR = 'cli-admin';

function printUsage() {
  console.log('Usage: node scripts/admin-reset-password.js --username <username>');
  console.log('');
  console.log('Options:');
  console.log('  --username <username>      Target username (required)');
  console.log('  --help                     Show this help message');
}

function parseArgs(argv) {
  const parsed = {
    username: '',
    help: false
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === '--help' || arg === '-h') {
      parsed.help = true;
      continue;
    }

    if (arg === '--username') {
      parsed.username = argv[index + 1] || '';
      index += 1;
      continue;
    }

    throw new Error(`Unknown argument: ${arg}`);
  }

  return parsed;
}

function confirmReset({ username }) {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      reject(new Error('Interactive confirmation required. Run this command from an interactive terminal (do not use docker compose exec -T).'));
      return;
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    rl.question(
      `Confirm password reset for user "${username}" as actor "${ACTOR}"? Type YES to continue: `,
      (answer) => {
        rl.close();
        resolve(answer.trim() === 'YES');
      }
    );

    rl.on('error', (err) => {
      rl.close();
      reject(err);
    });
  });
}

function generatePassword(length = 24) {
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '23456789';
  const symbols = '!@#$%^&*()-_=+';
  const all = `${upper}${lower}${digits}${symbols}`;

  const chars = [
    upper[crypto.randomInt(0, upper.length)],
    lower[crypto.randomInt(0, lower.length)],
    digits[crypto.randomInt(0, digits.length)],
    symbols[crypto.randomInt(0, symbols.length)]
  ];

  for (let index = chars.length; index < length; index += 1) {
    chars.push(all[crypto.randomInt(0, all.length)]);
  }

  for (let index = chars.length - 1; index > 0; index -= 1) {
    const swapIndex = crypto.randomInt(0, index + 1);
    const temp = chars[index];
    chars[index] = chars[swapIndex];
    chars[swapIndex] = temp;
  }

  return chars.join('');
}

async function main() {
  try {
    const args = parseArgs(process.argv.slice(2));

    if (args.help) {
      printUsage();
      process.exit(0);
    }

    if (!args.username) {
      throw new Error('Missing required --username argument');
    }

    const {
      getUserByUsername,
      updateUserPassword,
      logAuthAudit
    } = require('../db');

    const user = getUserByUsername(args.username);
    if (!user) {
      throw new Error(`No local user account exists with username "${args.username}". Check the username and try again.`);
    }

    const confirmed = await confirmReset({ username: user.username });

    if (!confirmed) {
      console.log('Cancelled: password reset aborted.');
      process.exit(0);
    }

    const newPassword = generatePassword(24);

    if (!newPassword || newPassword.length < 6) {
      throw new Error('Password must be at least 6 characters');
    }

    const result = updateUserPassword(user.id, newPassword);
    if (!result || result.changes === 0) {
      throw new Error('Password update did not change any rows');
    }

    logAuthAudit({
      success: true,
      authType: 'admin_cli',
      userId: user.id,
      username: user.username,
      roleName: user.role_name,
      sourceIp: 'docker-host',
      requestMethod: 'CLI',
      requestPath: '/host-cli/admin-reset-password',
      details: {
        event: 'admin_user_password_change_cli',
        actor: ACTOR
      },
      responseData: {
        success: true
      }
    });

    console.log(`Password updated for user: ${user.username}`);
    console.log(`Generated password: ${newPassword}`);
    process.exit(0);
  } catch (err) {
    console.error(`Password reset failed: ${err.message}`);

    if (
      err.message.startsWith('Missing required --username argument')
      || err.message.startsWith('Unknown argument:')
    ) {
      printUsage();
    }

    process.exit(1);
  }
}

main();