/**
 * E2E tests for workspace invites page.
 * Uses the authenticated fixture for full integration testing.
 */

import { test, expect } from './fixtures/test-setup';

test.describe('Invites Page - Unauthenticated', () => {
  test('should redirect to import when not authenticated', async ({ page }) => {
    await page.goto('/workspaces/test-workspace/invites');

    // Should be redirected to import
    await expect(page).toHaveURL(/\/import/);
  });
});

test.describe('Invites Page - Authenticated', () => {
  test('should show invites page with create button', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/invites`);

    // Should show the invites heading
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();

    // Should have create invite button
    await expect(page.getByRole('button', { name: /Create Invite/i })).toBeVisible();

    // Should show breadcrumb
    const breadcrumb = page.locator('.breadcrumbs');
    await expect(breadcrumb.getByRole('link', { name: 'Workspaces' })).toBeVisible();
    await expect(breadcrumb.getByRole('link', { name: workspaceName })).toBeVisible();
    await expect(breadcrumb.getByText('Invites')).toBeVisible();
  });

  test('should show how invites work section', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/invites`);
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();

    // Should show the how invites work section
    await expect(page.getByRole('heading', { name: 'How Invites Work' })).toBeVisible();

    // Check for step headings (using h3 elements)
    await expect(page.getByRole('heading', { name: 'Create an invite' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Share the code' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'They join the workspace' })).toBeVisible();
  });

  test('should show invite team members card', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/invites`);
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();

    // Should show the invite team members card
    await expect(page.getByText('Invite Team Members')).toBeVisible();
    await expect(page.getByText(/Create an invite link to add team members/i)).toBeVisible();
  });

  test('should create invite and show code', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/invites`);
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();

    // Click create invite button
    await page.getByRole('button', { name: /Create Invite/i }).click();

    // Wait for invite to be created (should show success message)
    await expect(page.getByText(/Invite Created!/i)).toBeVisible({ timeout: 15000 });

    // Should show the invite code
    await expect(page.getByText(/inv_/)).toBeVisible();

    // Should show warning about code being shown only once
    await expect(page.getByText(/This code will only be shown once/i)).toBeVisible();

    // Should have copy button
    await expect(page.getByRole('button').filter({ has: page.locator('svg') })).toBeVisible();
  });

  test('should be able to create multiple invites', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/invites`);
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();

    // Create first invite
    await page.getByRole('button', { name: /Create Invite/i }).click();
    await expect(page.getByText(/Invite Created!/i)).toBeVisible({ timeout: 15000 });

    // Get the first invite code
    const firstCode = await page.locator('code').textContent();

    // Create another invite (button should still be available)
    await page.getByRole('button', { name: /Create Invite/i }).click();
    await expect(page.getByText(/Invite Created!/i)).toBeVisible({ timeout: 15000 });

    // Get the second invite code - should be different
    const secondCode = await page.locator('code').textContent();

    // The codes should be different (each invite is unique)
    expect(firstCode).not.toBe(secondCode);
  });
});

test.describe('Invites Page - Navigation', () => {
  test('should navigate from projects page to invites', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Click invite link
    await page.getByRole('link', { name: /Invite/i }).click();

    // Should be on invites page
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();
  });

  test('should navigate back to projects via breadcrumb', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/invites`);
    await expect(page.getByRole('heading', { name: /Workspace Invites/i })).toBeVisible();

    // Click workspace in breadcrumb
    const breadcrumb = page.locator('.breadcrumbs');
    await breadcrumb.getByRole('link', { name: workspaceName }).click();

    // Should be on projects page
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();
  });
});
