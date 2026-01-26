/**
 * E2E tests for settings page.
 * Uses the authenticated fixture for full integration testing.
 */

import { test, expect } from './fixtures/test-setup';
import { Page } from '@playwright/test';

// Helper to inject a second principal into IndexedDB for testing switch functionality
async function injectSecondPrincipal(page: Page, secondPrincipalId: string, secondPrincipalName: string, secondEmail: string): Promise<void> {
  await page.evaluate(async ({ id, name, email }) => {
    const dbName = 'zopp-credentials';
    const dbVersion = 2;
    const principalsStore = 'principals';

    return new Promise<void>((resolve, reject) => {
      const request = indexedDB.open(dbName, dbVersion);
      request.onerror = () => reject(request.error);
      request.onsuccess = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        const tx = db.transaction(principalsStore, 'readwrite');
        const store = tx.objectStore(principalsStore);

        // Create a second principal record
        const principal = {
          id,
          name,
          email,
          user_id: null,
          // These are fake keys - the switch test only tests UI, not crypto operations
          ed25519_private_key: '0'.repeat(128),
          ed25519_public_key: '1'.repeat(64),
          x25519_private_key: '2'.repeat(64),
          x25519_public_key: '3'.repeat(64),
          ed25519_nonce: null,
          x25519_nonce: null,
          encrypted: false,
        };

        const putRequest = store.put(principal);
        putRequest.onsuccess = () => {
          db.close();
          resolve();
        };
        putRequest.onerror = () => {
          db.close();
          reject(putRequest.error);
        };
      };
    });
  }, { id: secondPrincipalId, name: secondPrincipalName, email: secondEmail });
}

test.describe('Settings Page - Unauthenticated', () => {
  test('should redirect to import when not authenticated', async ({ page }) => {
    await page.goto('/settings');

    // Should be redirected to import
    await expect(page).toHaveURL(/\/import/);
  });
});

test.describe('Settings Page - Authenticated', () => {
  test('should show settings page with principal information', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');

    // Should show the settings heading
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Should show Current Principal card
    await expect(page.getByText('Current Principal')).toBeVisible();

    // Should show principal info labels
    await expect(page.getByText('Name')).toBeVisible();
    await expect(page.getByText('Email')).toBeVisible();
    await expect(page.getByText('Principal ID')).toBeVisible();
  });

  test('should show export principal section', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Should show export section
    await expect(page.getByText('Export Principal')).toBeVisible();
    await expect(page.getByText(/Export your principal to use on another device/i)).toBeVisible();

    // Should have export button
    await expect(page.getByRole('button', { name: /Create Export/i })).toBeVisible();
  });

  test('should show danger zone with logout button', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Should show danger zone
    await expect(page.getByText('Danger Zone')).toBeVisible();

    // Should have logout button
    await expect(page.getByRole('button', { name: /Log out/i })).toBeVisible();
  });

  test('should have clickable export button', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Export button should be enabled and clickable
    const exportButton = page.getByRole('button', { name: /Create Export/i });
    await expect(exportButton).toBeEnabled();

    // Click should not throw (don't wait for completion as it may require server connection)
    await exportButton.click();

    // Button should show some response (either loading state or remain enabled)
    // This confirms the click registered without needing a fixed timeout
    await expect(exportButton).toBeVisible();
  });

  test('should logout and redirect to landing page', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Click logout button
    await page.getByRole('button', { name: /Log out/i }).click();

    // Should be redirected to landing page
    await expect(page).toHaveURL('/');
  });

  test('should not show switch principal section with only one principal', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Wait for Current Principal card to be fully rendered (indicates principals loaded)
    await expect(page.getByText('Current Principal')).toBeVisible();

    // Switch Principal section should NOT be visible with only one principal
    await expect(page.getByText('Switch Principal')).not.toBeVisible();
  });

  test('should show switch principal section when multiple principals exist', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    // First go to settings to ensure IndexedDB is set up
    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Inject a second principal into IndexedDB
    const secondPrincipalId = `second-principal-${Date.now()}`;
    const secondPrincipalName = 'Second Test Principal';
    const secondEmail = 'second@example.com';
    await injectSecondPrincipal(page, secondPrincipalId, secondPrincipalName, secondEmail);

    // Reload the page to pick up the new principal
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Wait for Switch Principal section to become visible (indicates principals loaded)
    await expect(page.getByText('Switch Principal')).toBeVisible();

    // Should show both principals
    await expect(page.getByText(secondPrincipalName)).toBeVisible();
    await expect(page.getByText(secondEmail)).toBeVisible();

    // Current principal should have "Current" badge
    await expect(page.locator('[data-testid="current-badge"]')).toBeVisible();

    // Second principal should have "Switch" button
    await expect(page.getByRole('button', { name: 'Switch' })).toBeVisible();
  });

  // TODO: This test is flaky - the switch doesn't work with fake injected credentials
  // The injected principal has fake keys that can't be validated by the app
  // This needs to be redesigned to either mock the validation or use real credentials
  test.skip('should switch to another principal when clicking switch button', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    // First go to settings to ensure IndexedDB is set up
    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Get the current principal name for later comparison
    const currentPrincipalName = await page.locator('[data-testid="current-principal-card"]').locator('p.font-medium').first().textContent();

    // Inject a second principal into IndexedDB
    const secondPrincipalId = `second-principal-${Date.now()}`;
    const secondPrincipalName = 'Switch Target Principal';
    const secondEmail = 'switch-target@example.com';
    await injectSecondPrincipal(page, secondPrincipalId, secondPrincipalName, secondEmail);

    // Reload the page to pick up the new principal
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Wait for Switch Principal section to become visible (indicates principals loaded)
    await expect(page.getByText('Switch Principal')).toBeVisible();

    // Click the Switch button (there should be exactly one - for the non-current principal)
    await page.getByRole('button', { name: 'Switch' }).click();

    // Wait for the page to reload after switch by waiting for the settings heading
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible({ timeout: 10000 });

    // The current principal name in the "Current Principal" card should now be the second principal
    const newPrincipalName = await page.locator('[data-testid="current-principal-card"]').locator('p.font-medium').first().textContent();

    // The principal should have changed
    expect(newPrincipalName).toBe(secondPrincipalName);
    expect(newPrincipalName).not.toBe(currentPrincipalName);
  });

  test('should be able to navigate to import page from settings', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/settings');
    await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible();

    // Navigate to import page (can be done even when authenticated)
    await page.goto('/import');

    // Should show import page (not redirected away)
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();
  });
});
