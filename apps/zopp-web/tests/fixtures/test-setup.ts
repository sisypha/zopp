/**
 * Test setup utilities for Playwright E2E tests.
 *
 * These tests require the full zopp stack to be running:
 * 1. zopp-server (gRPC) - port 50051
 * 2. Envoy proxy (gRPC-web) - port 8080
 * 3. The web UI (trunk serve) - port 3000
 *
 * Quick start:
 *   # Terminal 1: Start backend services
 *   docker compose -f docker/docker-compose.web-dev.yaml up
 *
 *   # Terminal 2: Run E2E tests (web UI starts automatically via Playwright)
 *   cd apps/zopp-web && npm run test:e2e
 *
 * Set ZOPP_TEST_INVITE or DATABASE_URL environment variable for invite creation.
 */

import { test as base, Page } from '@playwright/test';
import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Get verification code from MailHog API.
 * Waits for email to arrive and extracts the 6-digit code.
 */
async function getVerificationCodeFromMailHog(apiUrl: string, toEmail: string, timeoutMs = 10000): Promise<string | null> {
  const startTime = Date.now();

  while (Date.now() - startTime < timeoutMs) {
    try {
      const response = await fetch(`${apiUrl}/messages`);
      if (!response.ok) continue;

      const data = await response.json();
      // Find email sent to this address (most recent first)
      const email = data.items?.reverse().find((msg: { To?: Array<{ Mailbox: string; Domain: string }> }) =>
        msg.To?.some(to => `${to.Mailbox}@${to.Domain}`.toLowerCase() === toEmail.toLowerCase())
      );

      if (email) {
        // Extract 6-digit code from email body
        const body = email.Content?.Body || '';
        const match = body.match(/\b(\d{6})\b/);
        if (match) {
          return match[1];
        }
      }
    } catch {
      // Retry on error
    }

    // Wait before retrying
    await new Promise(resolve => setTimeout(resolve, 500));
  }

  return null;
}

// Credentials structure matching what the web app expects
interface StoredCredentials {
  principal_id: string;
  ed25519_private_key: string;
  ed25519_public_key: string;
  x25519_private_key: string;
  x25519_public_key: string;
  server_url: string;
}

export interface TestContext {
  serverUrl: string;
  grpcWebUrl: string;
  testDir: string;
  credentials: StoredCredentials;
  cliBin: string;
  userHomeDir: string;
  // Test data names
  workspaceName: string;
  projectName: string;
  environmentName: string;
}

// Check if the required services are running with retries
async function checkServicesRunning(): Promise<{ grpcWebUrl: string; serverUrl: string } | null> {
  // Check Envoy gRPC-web proxy (default: localhost:8080)
  const grpcWebUrl = process.env.ZOPP_GRPC_WEB_URL || 'http://localhost:8080';
  const serverUrl = process.env.ZOPP_SERVER_URL || 'http://localhost:50051';

  // Retry a few times in case of transient connection issues
  const maxRetries = 3;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Try to connect to Envoy - any response means it's running
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      const response = await fetch(grpcWebUrl, {
        method: 'OPTIONS',
        signal: controller.signal,
      });
      clearTimeout(timeoutId);
      // Envoy should respond (even with an error for OPTIONS)
      return { grpcWebUrl, serverUrl };
    } catch (e) {
      if (attempt < maxRetries) {
        // Wait a bit before retrying
        await new Promise(resolve => setTimeout(resolve, 500));
        continue;
      }
      return null;
    }
  }
  return null;
}

// Set up test user and data using the CLI
export async function setupTestData(serverUrl: string): Promise<TestContext> {
  // Create temp directory for test user
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'zopp-playwright-'));
  const userHomeDir = path.join(testDir, 'user-home');
  fs.mkdirSync(userHomeDir, { recursive: true });

  // Find CLI binary
  // __dirname = apps/zopp-web/tests/fixtures, so go up 4 levels to project root
  const projectRoot = path.resolve(__dirname, '../../../..');
  let cliBin = path.join(projectRoot, 'target/debug/zopp');
  let serverBin = path.join(projectRoot, 'target/debug/zopp-server');

  if (!fs.existsSync(cliBin)) {
    cliBin = path.join(projectRoot, 'target/release/zopp');
    serverBin = path.join(projectRoot, 'target/release/zopp-server');
  }

  if (!fs.existsSync(cliBin)) {
    throw new Error(`Could not find zopp CLI binary. Run 'cargo build' first.`);
  }

  // Generate a unique test ID
  const testId = `test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  // Create a fresh invite for this worker using the server binary.
  // Each worker gets its own invite to avoid race conditions.
  let inviteToken: string;

  // Determine database URL - check env var, then look for default zopp.db
  let dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    const defaultDbPath = path.join(projectRoot, 'zopp.db');
    if (fs.existsSync(defaultDbPath)) {
      dbUrl = `sqlite://${defaultDbPath}`;
    }
  }

  if (dbUrl && fs.existsSync(serverBin)) {
    try {
      inviteToken = execSync(`${serverBin} invite create --expires-hours 1 --plain`, {
        env: { ...process.env, DATABASE_URL: dbUrl },
      }).toString().trim();
    } catch (e) {
      throw new Error(
        `Could not create test invite using server binary.\n` +
        `DATABASE_URL: ${dbUrl}\n` +
        `Server binary: ${serverBin}\n` +
        `Error: ${e}`
      );
    }
  } else if (process.env.ZOPP_TEST_INVITE) {
    // Fallback to environment variable if provided (but warn this may cause issues with multiple workers)
    inviteToken = process.env.ZOPP_TEST_INVITE;
    console.warn('Using ZOPP_TEST_INVITE from environment. This may cause issues with parallel workers.');
  } else {
    throw new Error(
      'Could not create test invite. Either:\n' +
      '1. Run zopp-server with default zopp.db database\n' +
      '2. Set DATABASE_URL environment variable\n' +
      '3. Set ZOPP_TEST_INVITE (not recommended for parallel tests)'
    );
  }

  const email = `${testId}@example.com`;
  const principalDeviceName = `${testId}-device`;

  // Check if email verification is enabled by environment variable
  const mailhogApiUrl = process.env.MAILHOG_API_URL;
  const isVerificationEnabled = !!mailhogApiUrl;

  if (isVerificationEnabled) {
    // Email verification flow:
    // 1. First join attempt with invalid code triggers verification email
    // 2. Get code from MailHog
    // 3. Join with correct code

    // Step 1: Trigger verification email (use invalid code to fail but still trigger email send)
    try {
      execSync(`${cliBin} --server ${serverUrl} --use-file-storage join "${inviteToken}" ${email} --principal ${principalDeviceName} --verification-code 000000`, {
        env: { ...process.env, HOME: userHomeDir },
        stdio: 'pipe',
        maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      });
    } catch {
      // Expected to fail with invalid code - but email should be sent
    }

    // Step 2: Get verification code from MailHog
    const verificationCode = await getVerificationCodeFromMailHog(mailhogApiUrl, email);
    if (!verificationCode) {
      throw new Error(`Failed to get verification code from MailHog for ${email}`);
    }

    // Step 3: Join with correct code
    execSync(`${cliBin} --server ${serverUrl} --use-file-storage join "${inviteToken}" ${email} --principal ${principalDeviceName} --verification-code ${verificationCode}`, {
      env: { ...process.env, HOME: userHomeDir },
      stdio: 'pipe',
      maxBuffer: 10 * 1024 * 1024,
    });
  } else {
    // No verification - direct join
    execSync(`${cliBin} --server ${serverUrl} --use-file-storage join "${inviteToken}" ${email} --principal ${principalDeviceName}`, {
      env: { ...process.env, HOME: userHomeDir },
      stdio: 'pipe',
      maxBuffer: 10 * 1024 * 1024,
    });
  }

  // Read credentials from CLI config
  const configPath = path.join(userHomeDir, '.zopp', 'config.json');
  const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));

  // Find the current principal - config uses 'principals' array with 'current_principal' name
  const principalName = config.current_principal;
  const principal = config.principals?.find((p: { name: string }) => p.name === principalName);

  if (!principal) {
    throw new Error(`No principal found in config after join. Config: ${JSON.stringify(config, null, 2)}`);
  }

  // Debug: log the principal keys to verify they exist
  console.log('Principal ID:', principal.id);
  console.log('Has private_key:', !!principal.private_key);
  console.log('Has public_key:', !!principal.public_key);
  console.log('Has x25519_private_key:', !!principal.x25519_private_key);
  console.log('Has x25519_public_key:', !!principal.x25519_public_key);
  console.log('private_key length:', principal.private_key?.length);
  console.log('x25519_private_key length:', principal.x25519_private_key?.length);

  const grpcWebUrl = process.env.ZOPP_GRPC_WEB_URL || 'http://localhost:8080';

  const credentials: StoredCredentials = {
    principal_id: principal.id,
    ed25519_private_key: principal.private_key,
    ed25519_public_key: principal.public_key,
    x25519_private_key: principal.x25519_private_key,
    x25519_public_key: principal.x25519_public_key,
    server_url: grpcWebUrl, // Web app connects via gRPC-web proxy
  };

  // Create test workspace, project, environment
  const wsName = `ws-${testId}`;
  const projName = `proj-${testId}`;
  const envName = `env-${testId}`;

  execSync(`${cliBin} --server ${serverUrl} --use-file-storage workspace create ${wsName}`, {
    env: { ...process.env, HOME: userHomeDir },
  });

  execSync(`${cliBin} --server ${serverUrl} --use-file-storage project create -w ${wsName} ${projName}`, {
    env: { ...process.env, HOME: userHomeDir },
  });

  execSync(`${cliBin} --server ${serverUrl} --use-file-storage environment create -w ${wsName} -p ${projName} ${envName}`, {
    env: { ...process.env, HOME: userHomeDir },
  });

  // Create a test secret
  execSync(`${cliBin} --server ${serverUrl} --use-file-storage secret set -w ${wsName} -p ${projName} -e ${envName} TEST_SECRET initial-value`, {
    env: { ...process.env, HOME: userHomeDir },
  });

  // Return test context with all data
  return {
    serverUrl,
    grpcWebUrl,
    testDir,
    credentials,
    cliBin,
    userHomeDir,
    workspaceName: wsName,
    projectName: projName,
    environmentName: envName,
  };
}

// Inject credentials into the browser's IndexedDB
// Must match the structure in src/services/storage.rs
export async function injectCredentials(page: Page, credentials: StoredCredentials): Promise<void> {
  await page.evaluate(async (creds) => {
    // Match the app's IndexedDB structure (version 2)
    const dbName = 'zopp-credentials';
    const dbVersion = 2;
    const principalsStore = 'principals';
    const metaStore = 'meta';

    return new Promise<void>((resolve, reject) => {
      const request = indexedDB.open(dbName, dbVersion);

      request.onerror = () => reject(request.error);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create principals store if it doesn't exist
        if (!db.objectStoreNames.contains(principalsStore)) {
          const store = db.createObjectStore(principalsStore, { keyPath: 'id' });
          store.createIndex('name', 'name', { unique: false });
        }

        // Create meta store if it doesn't exist
        if (!db.objectStoreNames.contains(metaStore)) {
          db.createObjectStore(metaStore);
        }
      };

      request.onsuccess = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Store the principal credentials
        const tx1 = db.transaction(principalsStore, 'readwrite');
        const store1 = tx1.objectStore(principalsStore);

        // Create a principal record matching StoredPrincipal structure
        const principal = {
          id: creds.principal_id,
          name: 'test-principal',
          email: 'test@example.com',
          user_id: null,
          ed25519_private_key: creds.ed25519_private_key,
          ed25519_public_key: creds.ed25519_public_key,
          x25519_private_key: creds.x25519_private_key,
          x25519_public_key: creds.x25519_public_key,
          ed25519_nonce: null,
          x25519_nonce: null,
          encrypted: false, // Keys are not encrypted in test
        };

        // Debug log the principal being stored
        console.log('[Test Setup] Storing principal:', JSON.stringify({
          id: principal.id,
          x25519_private_key_length: principal.x25519_private_key?.length,
          x25519_public_key_length: principal.x25519_public_key?.length,
          ed25519_private_key_length: principal.ed25519_private_key?.length,
          encrypted: principal.encrypted
        }));

        const putRequest = store1.put(principal);

        putRequest.onsuccess = () => {
          // Set the current principal ID in meta store
          const tx2 = db.transaction(metaStore, 'readwrite');
          const store2 = tx2.objectStore(metaStore);
          const metaRequest = store2.put(creds.principal_id, 'current_principal_id');

          metaRequest.onsuccess = () => {
            db.close();
            resolve();
          };
          metaRequest.onerror = () => {
            db.close();
            reject(metaRequest.error);
          };
        };
        putRequest.onerror = () => {
          db.close();
          reject(putRequest.error);
        };
      };
    });
  }, credentials);

  // Also set in localStorage as a fallback/signal
  await page.evaluate((creds) => {
    localStorage.setItem('zopp_server_url', creds.server_url);
    localStorage.setItem('zopp_authenticated', 'true');
  }, credentials);
}

// Clean up test environment
export async function teardownTestEnvironment(ctx: TestContext): Promise<void> {
  // Clean up test directory
  try {
    fs.rmSync(ctx.testDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

// Extended test fixture with authenticated context
export const test = base.extend<{
  testContext: TestContext;
  authenticatedPage: Page;
}>({
  testContext: [async ({}, use) => {
    // Check if services are running
    const services = await checkServicesRunning();
    if (!services) {
      console.log('⚠️  Skipping E2E tests - zopp services not running');
      console.log('   Start with: docker compose -f docker/docker-compose.dev.yaml up');
      // Skip the test by returning early
      test.skip();
      return;
    }

    const ctx = await setupTestData(services.serverUrl);
    await use(ctx);
    await teardownTestEnvironment(ctx);
  }, { scope: 'worker' }],

  authenticatedPage: async ({ page, testContext }, use) => {
    // Navigate to any page first to initialize the browser context
    await page.goto('/');

    // Inject credentials
    await injectCredentials(page, testContext.credentials);

    // Reload to pick up the credentials
    await page.reload();

    await use(page);
  },
});

export { expect } from '@playwright/test';
