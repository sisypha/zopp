/**
 * E2E tests for settings page.
 * Uses the authenticated fixture for full integration testing.
 */

import { test, expect } from './fixtures/test-setup';

test.describe('Settings Page - Unauthenticated', () => {
  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/settings');

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/);
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

    // Give a moment for the click to register
    await page.waitForTimeout(500);
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
});
