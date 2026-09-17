import { argv, exit, stderr, stdout } from 'node:process';

const latest = argv[2] ?? '';

if (latest === '') {
  stdout.write('v1.0.0\n');
  exit(0);
}

const parts = /^v(\d+)\.(\d+)\.(\d+)$/.exec(latest);
if (parts === null) {
  stderr.write(
    `the latest release is ${latest}, which is not vMAJOR.MINOR.PATCH, so the next one cannot be numbered\n`,
  );
  exit(1);
}

stdout.write(`v${parts[1]}.${parts[2]}.${String(Number(parts[3]) + 1)}\n`);
