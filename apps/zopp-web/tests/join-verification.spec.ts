/**
 * Email Verification E2E tests for the web app.
 *
 * Tests the complete join flow with email verification:
 * 1. User fills in the join form (invite token, email, device name)
 * 2. Server requires email verification -> verification code UI appears
 * 3. User enters verification code from email
 * 4. Registration completes and user is authenticated
 *
 * Prerequisites:
 *   # Start MailHog (shared with CLI E2E tests)
 *   docker compose -f docker/docker-compose.test.yaml up -d
 *
 *   # Start the backend services with verification enabled
 *   ZOPP_EMAIL_VERIFICATION_REQUIRED=true \
 *   ZOPP_EMAIL_PROVIDER=smtp \
 *   SMTP_HOST=127.0.0.1 \
 *   SMTP_PORT=1025 \
 *   SMTP_USE_TLS=false \
 *   ZOPP_EMAIL_FROM=test@example.com \
 *   cargo run --bin zopp-server serve
 *
 *   # Run the web UI
 *   cd apps/zopp-web && npm run dev
 *
 *   # Run the tests
 *   cd apps/zopp-web && npm run test:e2e -- --grep verification
 *
 * Note: These tests share MailHog with the CLI E2E tests (docker/docker-compose.test.yaml)
 */

import { test, expect, Page } from '@playwright/test';
import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// Configuration
const GRPC_WEB_URL = process.env.ZOPP_GRPC_WEB_URL || 'http://localhost:8080';
const MAILHOG_API_URL = process.env.MAILHOG_API_URL || 'http://localhost:8025/api/v2';

interface MailHogMessage {
  ID: string;
  From: { Mailbox: string; Domain: string };
  To: Array<{ Mailbox: string; Domain: string }>;
  Content: {
    Headers: Record<string, string[]>;
    Body: string;
  };
}

interface MailHogResponse {
  total: number;
  count: number;
  start: number;
  items: MailHogMessage[];
}

/**
 * Check if the verification test stack is running
 */
async function isVerificationStackRunning(): Promise<boolean> {
  try {
    // Check if Envoy is responding
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    await fetch(GRPC_WEB_URL, { method: 'OPTIONS', signal: controller.signal });
    clearTimeout(timeoutId);
    return true;
  } catch {
    return false;
  }
}

/**
 * Create an invite token using the server binary or docker exec
 */
async function createInviteToken(): Promise<string> {
  // First check if ZOPP_VERIFICATION_TEST_INVITE is set
  if (process.env.ZOPP_VERIFICATION_TEST_INVITE) {
    return process.env.ZOPP_VERIFICATION_TEST_INVITE;
  }

  // Try to find server binary
  const projectRoot = path.resolve(__dirname, '../../..');
  const serverBin = fs.existsSync(path.join(projectRoot, 'target/debug/zopp-server'))
    ? path.join(projectRoot, 'target/debug/zopp-server')
    : path.join(projectRoot, 'target/release/zopp-server');

  // Try to find the database
  const dbPath = path.join(projectRoot, 'zopp.db');
  if (fs.existsSync(serverBin) && fs.existsSync(dbPath)) {
    try {
      return execSync(`${serverBin} invite create --expires-hours 1 --plain`, {
        env: { ...process.env, DATABASE_URL: `sqlite://${dbPath}` },
      }).toString().trim();
    } catch {
      // Fall through to docker exec
    }
  }

  // Try docker exec
  try {
    return execSync(
      'docker compose -f docker/docker-compose.web-verification-test.yaml exec -T zopp-server /app/zopp-server invite create --expires-hours 1 --plain',
      { cwd: projectRoot }
    ).toString().trim();
  } catch (e) {
    throw new Error(
      'Could not create invite token. Either:\n' +
      '1. Set ZOPP_VERIFICATION_TEST_INVITE environment variable\n' +
      '2. Start the verification test stack: docker compose -f docker/docker-compose.web-verification-test.yaml up -d\n' +
      `Error: ${e}`
    );
  }
}

/**
 * Get verification code from MailHog API
 */
async function getVerificationCodeFromMailhog(email: string, timeoutMs: number = 10000): Promise<string> {
  const start = Date.now();

  while (Date.now() - start < timeoutMs) {
    try {
      const response = await fetch(`${MAILHOG_API_URL}/messages`);
      if (!response.ok) {
        await new Promise(resolve => setTimeout(resolve, 500));
        continue;
      }

      const data: MailHogResponse = await response.json();

      // Find email to the target address
      const message = data.items.find(msg =>
        msg.To.some(to => `${to.Mailbox}@${to.Domain}`.toLowerCase() === email.toLowerCase())
      );

      if (message) {
        // Extract 6-digit code from email body
        const match = message.Content.Body.match(/\b(\d{6})\b/);
        if (match) {
          return match[1];
        }
      }
    } catch {
      // Retry on error
    }

    await new Promise(resolve => setTimeout(resolve, 500));
  }

  throw new Error(`No verification email found for ${email} within ${timeoutMs}ms`);
}

/**
 * Clear all emails from MailHog
 */
async function clearMailhog(): Promise<void> {
  try {
    await fetch(`${MAILHOG_API_URL}/messages`, { method: 'DELETE' });
  } catch {
    // Ignore errors
  }
}

test.describe('Join with Email Verification', () => {
  test.beforeAll(async () => {
    // Check if verification stack is running
    const isRunning = await isVerificationStackRunning();
    if (!isRunning) {
      console.log('');
      console.log('⚠️  Verification test stack not running. Skipping verification tests.');
      console.log('   Start with: docker compose -f docker/docker-compose.web-verification-test.yaml up -d');
      console.log('');
      test.skip();
    }
  });

  test.beforeEach(async () => {
    // Clear MailHog before each test
    await clearMailhog();
  });

  test('should show verification code input after submitting join form', async ({ page }) => {
    const inviteToken = await createInviteToken();
    const testEmail = `test-${Date.now()}@example.com`;
    const deviceName = 'Test Device';

    // Navigate to join/invite page
    await page.goto('/invite');

    // Fill in the form
    await page.getByPlaceholder(/inv_/i).fill(inviteToken);
    await page.getByPlaceholder(/you@example.com/i).fill(testEmail);
    await page.getByPlaceholder(/My Laptop/i).fill(deviceName);

    // Submit the form
    await page.getByRole('button', { name: /Create Principal/i }).click();

    // Should show verification code input (use heading which is unique)
    await expect(page.getByRole('heading', { name: /Verify Your Email/i })).toBeVisible({ timeout: 10000 });
    await expect(page.getByPlaceholder('123456')).toBeVisible();
  });

  test('should complete registration with valid verification code', async ({ page }) => {
    const inviteToken = await createInviteToken();
    const testEmail = `test-${Date.now()}@example.com`;
    const deviceName = 'Test Device';

    // Navigate to join/invite page
    await page.goto('/invite');

    // Fill in the form
    await page.getByPlaceholder(/inv_/i).fill(inviteToken);
    await page.getByPlaceholder(/you@example.com/i).fill(testEmail);
    await page.getByPlaceholder(/My Laptop/i).fill(deviceName);

    // Submit the form
    await page.getByRole('button', { name: /Create Principal/i }).click();

    // Wait for verification code input to appear (use heading which is unique)
    await expect(page.getByRole('heading', { name: /Verify Your Email/i })).toBeVisible({ timeout: 10000 });

    // Get verification code from MailHog
    const verificationCode = await getVerificationCodeFromMailhog(testEmail);
    expect(verificationCode).toMatch(/^\d{6}$/);

    // Enter the verification code
    await page.getByPlaceholder('123456').fill(verificationCode);

    // Submit verification
    await page.getByRole('button', { name: /Verify/i }).click();

    // Should redirect to workspaces page on success
    await expect(page).toHaveURL(/\/settings/, { timeout: 10000 });
  });

  test('should show error for invalid verification code', async ({ page }) => {
    const inviteToken = await createInviteToken();
    const testEmail = `test-${Date.now()}@example.com`;
    const deviceName = 'Test Device';

    // Navigate to join/invite page
    await page.goto('/invite');

    // Fill in the form
    await page.getByPlaceholder(/inv_/i).fill(inviteToken);
    await page.getByPlaceholder(/you@example.com/i).fill(testEmail);
    await page.getByPlaceholder(/My Laptop/i).fill(deviceName);

    // Submit the form
    await page.getByRole('button', { name: /Create Principal/i }).click();

    // Wait for verification code input to appear (use heading which is unique)
    await expect(page.getByRole('heading', { name: /Verify Your Email/i })).toBeVisible({ timeout: 10000 });

    // Enter an invalid code
    await page.getByPlaceholder('123456').fill('000000');

    // Submit verification
    await page.getByRole('button', { name: /Verify/i }).click();

    // Should show error message
    await expect(page.getByText(/invalid|incorrect|wrong|attempts/i)).toBeVisible({ timeout: 5000 });

    // Should still be on the same page (not redirected)
    await expect(page).toHaveURL(/\/invite/);
  });

  test('should allow retrying with correct code after invalid attempt', async ({ page }) => {
    const inviteToken = await createInviteToken();
    const testEmail = `test-${Date.now()}@example.com`;
    const deviceName = 'Test Device';

    // Navigate to join/invite page
    await page.goto('/invite');

    // Fill in the form
    await page.getByPlaceholder(/inv_/i).fill(inviteToken);
    await page.getByPlaceholder(/you@example.com/i).fill(testEmail);
    await page.getByPlaceholder(/My Laptop/i).fill(deviceName);

    // Submit the form
    await page.getByRole('button', { name: /Create Principal/i }).click();

    // Wait for verification code input (use heading which is unique)
    await expect(page.getByRole('heading', { name: /Verify Your Email/i })).toBeVisible({ timeout: 10000 });

    // First attempt with invalid code
    await page.getByPlaceholder('123456').fill('000000');
    await page.getByRole('button', { name: /Verify/i }).click();

    // Should show error
    await expect(page.getByText(/invalid|incorrect|wrong|attempts/i)).toBeVisible({ timeout: 5000 });

    // Get the real verification code
    const verificationCode = await getVerificationCodeFromMailhog(testEmail);

    // Clear and enter correct code
    await page.getByPlaceholder('123456').clear();
    await page.getByPlaceholder('123456').fill(verificationCode);

    // Submit again
    await page.getByRole('button', { name: /Verify/i }).click();

    // Should redirect to workspaces page on success
    await expect(page).toHaveURL(/\/settings/, { timeout: 10000 });
  });
});
