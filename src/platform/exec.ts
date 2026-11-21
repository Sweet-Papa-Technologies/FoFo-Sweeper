import { execFile } from 'node:child_process';

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  error?: string;
}

export function execFileSafe(
  command: string,
  args: string[],
  options: {
    timeoutMs?: number;
    maxBuffer?: number;
    env?: NodeJS.ProcessEnv;
    cwd?: string;
  } = {}
): Promise<ExecResult> {
  const timeoutMs = options.timeoutMs ?? 60_000;
  const maxBuffer = options.maxBuffer ?? 32 * 1024 * 1024;

  return new Promise((resolve) => {
    execFile(
      command,
      args,
      {
        timeout: timeoutMs,
        maxBuffer,
        env: options.env ?? process.env,
        cwd: options.cwd,
        windowsHide: true,
        encoding: 'utf8',
      },
      (err, stdout, stderr) => {
        if (!err) {
          resolve({
            stdout: stdout ?? '',
            stderr: stderr ?? '',
            exitCode: 0,
            timedOut: false,
          });
          return;
        }
        const e = err as NodeJS.ErrnoException & { killed?: boolean; signal?: string; code?: number | string };
        const timedOut = Boolean(e.killed && (e.signal === 'SIGTERM' || e.signal === 'SIGKILL'));
        const exitCode = typeof e.code === 'number' ? e.code : 1;
        resolve({
          stdout: stdout ?? '',
          stderr: stderr ?? '',
          exitCode,
          timedOut,
          error: timedOut ? `Timed out after ${timeoutMs}ms` : e.message,
        });
      }
    );
  });
}
