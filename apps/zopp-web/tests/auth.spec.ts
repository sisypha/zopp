import { test, expect } from '@playwright/test';
import { test as authenticatedTest, expect as authenticatedExpect } from './fixtures/test-setup';

test.describe('Authentication - Unauthenticated', () => {
  test('should show import page at /import', async ({ page }) => {
    await page.goto('/import');

    // Should show the import principal form
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();

    // Should have export code and passphrase inputs
    await expect(page.getByPlaceholder(/Enter export code/i)).toBeVisible();
    await expect(page.getByPlaceholder(/Enter passphrase/i)).toBeVisible();

    // Should have import button
    await expect(page.getByRole('button', { name: /Import/i })).toBeVisible();

    // Should have link to invite page (join with invite token)
    await expect(page.getByRole('link', { name: /Join with Invite Token/i })).toBeVisible();
  });

  test('should show invite page at /invite', async ({ page }) => {
    await page.goto('/invite');

    // Should show the join workspace form
    await expect(page.getByRole('heading', { name: /Join Workspace/i })).toBeVisible();

    // Should have invite token, email, and device name inputs
    await expect(page.getByPlaceholder(/inv_/i)).toBeVisible();
    await expect(page.getByPlaceholder(/you@example.com/i)).toBeVisible();
    await expect(page.getByPlaceholder(/My Laptop/i)).toBeVisible();

    // Should have create principal button
    await expect(page.getByRole('button', { name: /Create Principal/i })).toBeVisible();

    // Should have link to import page
    await expect(page.getByRole('link', { name: /Import Existing Principal/i })).toBeVisible();
  });

  test('should navigate between import and invite pages', async ({ page }) => {
    // Start at import
    await page.goto('/import');
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();

    // Click link to invite (join with invite token)
    await page.getByRole('link', { name: /Join with Invite Token/i }).click();
    await expect(page.getByRole('heading', { name: /Join Workspace/i })).toBeVisible();

    // Click link back to import
    await page.getByRole('link', { name: /Import Existing Principal/i }).click();
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();
  });

  test('should show validation error when submitting empty import form', async ({ page }) => {
    await page.goto('/import');

    // Click import without filling in fields
    await page.getByRole('button', { name: /Import/i }).click();

    // Should show error message
    await expect(page.getByText(/Please enter both/i)).toBeVisible();
  });

  test('should show validation error when submitting empty invite form', async ({ page }) => {
    await page.goto('/invite');

    // Click create without filling in fields
    await page.getByRole('button', { name: /Create Principal/i }).click();

    // Should show error message
    await expect(page.getByText(/Please fill in all fields/i)).toBeVisible();
  });

  test('should redirect unauthenticated user from protected routes', async ({ page }) => {
    // Try to access settings page without being authenticated
    await page.goto('/settings');

    // Should be redirected to import
    await expect(page).toHaveURL(/\/import/);
  });
});

authenticatedTest.describe('Authentication - Authenticated', () => {
  authenticatedTest('should allow authenticated user to access import page for switching principals', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    // Navigate to import page while authenticated
    await page.goto('/import');

    // Should stay on import page (allows switching principals)
    await authenticatedExpect(page).toHaveURL(/\/import/);

    // Should show the import form
    await authenticatedExpect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();
  });
});

test.describe('Dashboard Navigation', () => {
  test('should show 404 page for unknown routes', async ({ page }) => {
    await page.goto('/unknown-route');

    // Should show 404 page
    await expect(page.getByRole('heading', { name: /Page Not Found/i })).toBeVisible();
    await expect(page.getByRole('link', { name: /Go Home/i })).toBeVisible();
  });
});
