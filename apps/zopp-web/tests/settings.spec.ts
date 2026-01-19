import { test, expect } from '@playwright/test';

test.describe('Settings', () => {
  // Note: These tests require auth state to be mocked.
  // The UI should redirect to login without proper auth.

  test('should redirect to login when not authenticated', async ({ page }) => {
    await page.goto('/settings');

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/);
  });

  test.skip('should show settings page when authenticated', async ({ page }) => {
    // TODO: Mock auth state to test authenticated page access
    await page.goto('/settings');

    // Should show the settings heading
    await expect(page.getByRole('heading', { name: /Settings/i })).toBeVisible();
  });

  test.skip('should show principal information', async ({ page }) => {
    // TODO: Mock auth state to test authenticated page access
    await page.goto('/settings');

    // Should show principal info card
    await expect(page.getByText(/Principal Information/i)).toBeVisible();

    // Should show principal ID, email, and device name labels
    await expect(page.getByText(/Principal ID/i)).toBeVisible();
    await expect(page.getByText(/Email/i)).toBeVisible();
    await expect(page.getByText(/Device Name/i)).toBeVisible();
  });

  test.skip('should show export principal section', async ({ page }) => {
    // TODO: Mock auth state to test authenticated page access
    await page.goto('/settings');

    // Should show export card
    await expect(page.getByText(/Export Principal/i)).toBeVisible();
    await expect(page.getByText(/Export your principal credentials/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /Export Principal/i })).toBeVisible();
  });

  test.skip('should show danger zone with logout button', async ({ page }) => {
    // TODO: Mock auth state to test authenticated page access
    await page.goto('/settings');

    // Should show danger zone
    await expect(page.getByText(/Danger Zone/i)).toBeVisible();
    await expect(page.getByRole('button', { name: /Logout/i })).toBeVisible();
  });

  test.skip('should start export process when clicking export button', async ({ page }) => {
    // TODO: Mock auth state and API response
    await page.goto('/settings');

    // Click export button
    await page.getByRole('button', { name: /Export Principal/i }).click();

    // Should show loading state
    await expect(page.getByRole('button', { name: /Export Principal/i })).toBeDisabled();

    // After API response, should show export code and passphrase
    // (This would need mocked API response)
  });

  test.skip('should redirect to login when clicking logout', async ({ page }) => {
    // TODO: Mock auth state
    await page.goto('/settings');

    // Click logout button
    await page.getByRole('button', { name: /Logout/i }).click();

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/);
  });
});
