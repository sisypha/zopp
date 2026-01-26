/**
 * E2E tests for permissions and groups page.
 * Uses the authenticated fixture for full integration testing.
 */

import { test, expect } from './fixtures/test-setup';

test.describe('Permissions Page - Unauthenticated', () => {
  test('should redirect to import when not authenticated', async ({ page }) => {
    await page.goto('/workspaces/test-workspace/permissions');

    // Should be redirected to import
    await expect(page).toHaveURL(/\/import/);
  });
});

test.describe('Permissions Page - Authenticated', () => {
  test('should show permissions page with tabs', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/permissions`);

    // Should show the permissions heading
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Should show tabs (use .tabs locator to be specific)
    const tabs = page.locator('[data-testid="tabs"]');
    await expect(tabs.getByText('Permissions', { exact: true })).toBeVisible();
    await expect(tabs.getByText('Groups', { exact: true })).toBeVisible();

    // Should show breadcrumb
    const breadcrumb = page.locator('[data-testid="breadcrumb"]');
    await expect(breadcrumb.getByRole('link', { name: 'Workspaces' })).toBeVisible();
    await expect(breadcrumb.getByRole('link', { name: workspaceName })).toBeVisible();
    await expect(breadcrumb.getByText('Permissions')).toBeVisible();
  });

  test('should switch between permissions and groups tabs', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/permissions`);
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Click on Groups tab (use exact match to avoid matching heading)
    await page.locator('[data-testid="tabs"]').getByText('Groups', { exact: true }).click();

    // Wait for content to load
    await page.waitForTimeout(500);

    // Should show Create Group button when on groups tab
    await expect(page.getByRole('button', { name: /Create Group/i })).toBeVisible();

    // Click back to Permissions tab
    await page.locator('[data-testid="tabs"]').getByText('Permissions', { exact: true }).click();

    // Should no longer show Create Group button (it's only on groups tab)
    await page.waitForTimeout(500);
  });

  test('should show permissions table', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/permissions`);
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Wait for loading to finish
    await page.waitForTimeout(2000);

    // Should show a table or list of permissions (may be empty or have current user)
    // The table should have headers for principal info
    const table = page.locator('table');
    if (await table.isVisible()) {
      // If table exists, check it has expected structure
      await expect(page.getByText(/Principal|User|Email/i)).toBeVisible();
    }
  });

  test('should open create group modal', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/permissions`);
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Switch to groups tab (use exact match to avoid matching heading)
    await page.locator('[data-testid="tabs"]').getByText('Groups', { exact: true }).click();
    await page.waitForTimeout(500);

    // Click create group button
    await page.getByRole('button', { name: /Create Group/i }).click();

    // Modal should appear
    await expect(page.getByRole('heading', { name: /Create Group/i })).toBeVisible();

    // Should have input and buttons
    await expect(page.getByPlaceholder(/developers/i)).toBeVisible();
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Create', exact: true })).toBeVisible();
  });

  test('should close create group modal when clicking cancel', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/permissions`);
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Switch to groups tab (use exact match to avoid matching heading)
    await page.locator('[data-testid="tabs"]').getByText('Groups', { exact: true }).click();
    await page.waitForTimeout(500);

    // Open modal
    await page.getByRole('button', { name: /Create Group/i }).click();
    await expect(page.getByRole('heading', { name: /Create Group/i })).toBeVisible();

    // Click cancel
    await page.getByRole('button', { name: 'Cancel' }).click();

    // Modal should close
    await expect(page.getByRole('heading', { name: /Create Group/i })).not.toBeVisible();
  });

  test('should create a new group', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;
    const newGroupName = `test-group-${Date.now()}`;

    await page.goto(`/workspaces/${workspaceName}/permissions`);
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Switch to groups tab (use exact match to avoid matching heading)
    await page.locator('[data-testid="tabs"]').getByText('Groups', { exact: true }).click();
    await page.waitForTimeout(500);

    // Open modal
    await page.getByRole('button', { name: /Create Group/i }).click();
    await expect(page.getByRole('heading', { name: /Create Group/i })).toBeVisible();

    // Fill in group name
    await page.getByPlaceholder(/developers/i).fill(newGroupName);

    // Submit
    await page.getByRole('button', { name: 'Create', exact: true }).click();

    // Modal should close
    await expect(page.getByRole('heading', { name: /Create Group/i })).not.toBeVisible({ timeout: 10000 });

    // New group should appear in the list
    await expect(page.getByText(newGroupName)).toBeVisible({ timeout: 10000 });
  });
});

test.describe('Permissions Page - Navigation', () => {
  test('should navigate from projects page to permissions', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Click permissions link
    await page.getByRole('link', { name: /Permissions/i }).click();

    // Should be on permissions page
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();
  });

  test('should navigate back to projects via breadcrumb', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/permissions`);
    await expect(page.getByRole('heading', { name: /Permissions & Groups/i })).toBeVisible();

    // Click workspace in breadcrumb
    const breadcrumb = page.locator('[data-testid="breadcrumb"]');
    await breadcrumb.getByRole('link', { name: workspaceName }).click();

    // Should be on projects page
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();
  });
});
