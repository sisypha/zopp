/**
 * Test setup for email verification E2E tests.
 *
 * This setup:
 * 1. Starts a mock SMTP server
 * 2. Starts zopp-server with email verification enabled
 * 3. Starts Envoy gRPC-web proxy
 * 4. Provides helpers to get verification codes from captured emails
 */

import { test as base, Page } from '@playwright/test';
import { execSync, execFileSync, spawn, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as net from 'net';
import { MockSmtpServer } from './mock-smtp';

// Find an available port
async function findAvailablePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address && typeof address === 'object') {
        const port = address.port;
        server.close(() => resolve(port));
      } else {
        reject(new Error('Failed to get port'));
      }
    });
    server.on('error', reject);
  });
}

// Wait for a server to be ready
async function waitForServer(url: string, timeoutMs: number = 30000): Promise<boolean> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 2000);
      const response = await fetch(url, { signal: controller.signal });
      clearTimeout(timeoutId);
      // Only return true if server responds successfully
      if (response.ok) {
        return true;
      }
    } catch {
      // Retry on network error
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  return false;
}

export interface VerificationTestContext {
  serverUrl: string;
  grpcWebUrl: string;
  testDir: string;
  inviteToken: string;
  mockSmtp: MockSmtpServer;
  serverProcess: ChildProcess;
  envoyProcess: ChildProcess | null;
  dbPath: string;
}

/**
 * Setup test environment with email verification enabled.
 * Starts zopp-server, mock SMTP, and optionally Envoy proxy.
 */
export async function setupVerificationTest(): Promise<VerificationTestContext> {
  // Find project root
  const projectRoot = path.resolve(__dirname, '../../../..');

  // Find binaries
  let serverBin = path.join(projectRoot, 'target/debug/zopp-server');
  if (!fs.existsSync(serverBin)) {
    serverBin = path.join(projectRoot, 'target/release/zopp-server');
  }
  if (!fs.existsSync(serverBin)) {
    throw new Error('zopp-server binary not found. Run: cargo build');
  }

  // Create temp directory
  const testId = `web-verify-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const testDir = path.join(os.tmpdir(), testId);
  fs.mkdirSync(testDir, { recursive: true });

  // Create SQLite database path
  const dbPath = path.join(testDir, 'zopp.db');
  const dbUrl = `sqlite://${dbPath}?mode=rwc`;

  // Start mock SMTP server
  const mockSmtp = new MockSmtpServer();
  const smtpPort = await mockSmtp.start();

  // Find available ports
  const serverPort = await findAvailablePort();
  const healthPort = await findAvailablePort();
  const envoyPort = await findAvailablePort();

  // Start zopp-server with email verification enabled
  const serverEnv = {
    ...process.env,
    DATABASE_URL: dbUrl,
    ZOPP_EMAIL_VERIFICATION_REQUIRED: 'true',
    ZOPP_EMAIL_PROVIDER: 'smtp',
    SMTP_HOST: '127.0.0.1',
    SMTP_PORT: smtpPort.toString(),
    SMTP_USE_TLS: 'false',
    ZOPP_EMAIL_FROM: 'test@example.com',
  };

  const serverProcess = spawn(serverBin, [
    'serve',
    '--addr', `0.0.0.0:${serverPort}`,
    '--health-addr', `0.0.0.0:${healthPort}`,
  ], {
    env: serverEnv,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  // Log server output for debugging
  serverProcess.stdout?.on('data', (data) => {
    if (process.env.DEBUG) console.log(`[server] ${data}`);
  });
  serverProcess.stderr?.on('data', (data) => {
    if (process.env.DEBUG) console.error(`[server] ${data}`);
  });

  // Wait for server to be ready
  const serverReady = await waitForServer(`http://127.0.0.1:${healthPort}/readyz`);
  if (!serverReady) {
    serverProcess.kill();
    await mockSmtp.stop();
    throw new Error('Server failed to start within timeout');
  }

  // Create an invite token
  const inviteToken = execSync(`${serverBin} invite create --expires-hours 1 --plain`, {
    env: { ...process.env, DATABASE_URL: dbUrl },
  }).toString().trim();

  // For now, skip Envoy and test against gRPC directly
  // In production tests, you'd start Envoy here
  const envoyProcess = null;

  return {
    serverUrl: `http://127.0.0.1:${serverPort}`,
    grpcWebUrl: `http://127.0.0.1:${serverPort}`, // Use server port directly since Envoy isn't running
    testDir,
    inviteToken,
    mockSmtp,
    serverProcess,
    envoyProcess,
    dbPath,
  };
}

/**
 * Cleanup test environment
 */
export async function teardownVerificationTest(ctx: VerificationTestContext): Promise<void> {
  // Stop server
  if (ctx.serverProcess) {
    ctx.serverProcess.kill('SIGTERM');
    // Give it time to shutdown gracefully
    await new Promise(resolve => setTimeout(resolve, 500));
    ctx.serverProcess.kill('SIGKILL');
  }

  // Stop Envoy if running
  if (ctx.envoyProcess) {
    ctx.envoyProcess.kill('SIGTERM');
    await new Promise(resolve => setTimeout(resolve, 200));
    ctx.envoyProcess.kill('SIGKILL');
  }

  // Stop mock SMTP
  await ctx.mockSmtp.stop();

  // Cleanup test directory
  try {
    fs.rmSync(ctx.testDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Get verification code from the database directly.
 * This is a fallback if mock SMTP doesn't capture the email.
 */
export function getVerificationCodeFromDb(dbPath: string, email: string): string | null {
  try {
    // Use execFileSync to avoid shell injection - email is passed via SQL query directly
    // Escape single quotes in email for SQL safety
    const escapedEmail = email.replace(/'/g, "''");
    const result = execFileSync(
      'sqlite3',
      [dbPath, `SELECT code FROM email_verifications WHERE email = '${escapedEmail}' ORDER BY created_at DESC LIMIT 1;`],
      { encoding: 'utf-8' }
    ).trim();
    return result || null;
  } catch {
    return null;
  }
}

// Extended test fixture for verification tests
export const verificationTest = base.extend<{
  verificationContext: VerificationTestContext;
}>({
  verificationContext: [async ({}, use) => {
    const ctx = await setupVerificationTest();
    await use(ctx);
    await teardownVerificationTest(ctx);
  }, { scope: 'worker', timeout: 60000 }],
});

export { expect } from '@playwright/test';
