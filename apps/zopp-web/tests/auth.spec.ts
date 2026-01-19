import { test, expect } from '@playwright/test';

test.describe('Authentication', () => {
  test('should show login page at /login', async ({ page }) => {
    await page.goto('/login');

    // Should show the import principal form
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();

    // Should have export code and passphrase inputs
    await expect(page.getByPlaceholder(/Enter export code/i)).toBeVisible();
    await expect(page.getByPlaceholder(/Enter passphrase/i)).toBeVisible();

    // Should have import button
    await expect(page.getByRole('button', { name: /Import/i })).toBeVisible();

    // Should have link to register page
    await expect(page.getByRole('link', { name: /Create New Principal/i })).toBeVisible();
  });

  test('should show register page at /register', async ({ page }) => {
    await page.goto('/register');

    // Should show the join workspace form
    await expect(page.getByRole('heading', { name: /Join Workspace/i })).toBeVisible();

    // Should have invite token, email, and device name inputs
    await expect(page.getByPlaceholder(/zopp-invite/i)).toBeVisible();
    await expect(page.getByPlaceholder(/you@example.com/i)).toBeVisible();
    await expect(page.getByPlaceholder(/My Laptop/i)).toBeVisible();

    // Should have create principal button
    await expect(page.getByRole('button', { name: /Create Principal/i })).toBeVisible();

    // Should have link to login page
    await expect(page.getByRole('link', { name: /Import Existing Principal/i })).toBeVisible();
  });

  test('should navigate between login and register pages', async ({ page }) => {
    // Start at login
    await page.goto('/login');
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();

    // Click link to register
    await page.getByRole('link', { name: /Create New Principal/i }).click();
    await expect(page.getByRole('heading', { name: /Join Workspace/i })).toBeVisible();

    // Click link back to login
    await page.getByRole('link', { name: /Import Existing Principal/i }).click();
    await expect(page.getByRole('heading', { name: /Import Principal/i })).toBeVisible();
  });

  test('should show validation error when submitting empty login form', async ({ page }) => {
    await page.goto('/login');

    // Click import without filling in fields
    await page.getByRole('button', { name: /Import/i }).click();

    // Should show error message
    await expect(page.getByText(/Please enter both/i)).toBeVisible();
  });

  test('should show validation error when submitting empty register form', async ({ page }) => {
    await page.goto('/register');

    // Click create without filling in fields
    await page.getByRole('button', { name: /Create Principal/i }).click();

    // Should show error message
    await expect(page.getByText(/Please fill in all fields/i)).toBeVisible();
  });

  test('should redirect unauthenticated user from protected routes', async ({ page }) => {
    // Try to access workspaces page without being logged in
    await page.goto('/workspaces');

    // Should be redirected to login
    await expect(page).toHaveURL(/\/login/);
  });

  test.skip('should redirect authenticated user away from login page', async ({ page }) => {
    // TODO: Implement after auth state is properly set up
    // This test will mock the auth state and verify redirect behavior
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
