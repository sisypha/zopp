/**
 * E2E tests for secrets management in the web UI.
 * Tests create, read, edit, and delete operations.
 *
 * Quick start:
 *   ./scripts/run-web-e2e.sh
 *
 * Or manually:
 *   1. docker compose -f docker/docker-compose.web-dev.yaml up -d
 *   2. export ZOPP_TEST_INVITE=$(docker compose exec zopp-server zopp-server invite create --plain)
 *   3. cd apps/zopp-web && npm run test:e2e
 */

import { test, expect } from './fixtures/test-setup';

test.describe('Secrets Page - Authenticated', () => {
  test('should navigate to secrets page and see existing secret', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    // Capture browser console logs
    page.on('console', msg => {
      console.log(`[Browser ${msg.type()}]`, msg.text());
    });

    // Navigate to the secrets page
    const url = `/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`;
    console.log('Navigating to:', url);
    await page.goto(url);

    // Wait for the page to load
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Take a screenshot to debug what's on the page
    await page.screenshot({ path: 'test-results/debug-secrets-page.png' });

    // Wait a bit for secrets to load
    await page.waitForTimeout(2000);

    // Take another screenshot after waiting
    await page.screenshot({ path: 'test-results/debug-secrets-page-after-wait.png' });

    // Check what's on the page
    const pageContent = await page.content();
    console.log('Page has table:', pageContent.includes('<table'));
    console.log('Page has TEST_SECRET:', pageContent.includes('TEST_SECRET'));
    console.log('Page has "No secrets":', pageContent.includes('No secrets'));
    console.log('Page has error alert:', pageContent.includes('alert-error'));

    // Wait for secrets to load (table should appear)
    await expect(page.locator('table')).toBeVisible({ timeout: 10000 });

    // Should see the test secret we created
    await expect(page.getByText('TEST_SECRET')).toBeVisible({ timeout: 10000 });

    // Value should be hidden by default
    await expect(page.getByText('********')).toBeVisible();
  });

  test('should toggle secret visibility', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Wait for secrets table to load
    await expect(page.locator('table')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('TEST_SECRET')).toBeVisible({ timeout: 10000 });

    // Value should be hidden initially
    await expect(page.getByText('********')).toBeVisible();

    // Click the visibility toggle button (eye icon)
    await page.getByRole('button', { name: /toggle visibility/i }).first().click();

    // Value should now be visible
    await expect(page.getByText('initial-value')).toBeVisible();

    // Click again to hide
    await page.getByRole('button', { name: /toggle visibility/i }).first().click();

    // Value should be hidden again
    await expect(page.getByText('********')).toBeVisible();
  });

  test('should open edit modal when clicking edit button', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Wait for secrets table
    await expect(page.locator('table')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('TEST_SECRET')).toBeVisible({ timeout: 10000 });

    // Click the edit button (pencil icon)
    await page.getByRole('button', { name: /edit secret/i }).first().click();

    // Edit modal should appear
    await expect(page.getByRole('heading', { name: 'Edit Secret' })).toBeVisible();

    // Key should be displayed but disabled
    const keyInput = page.locator('input[disabled]');
    await expect(keyInput).toHaveValue('TEST_SECRET');

    // Value should be in the textarea
    const valueTextarea = page.locator('textarea');
    await expect(valueTextarea).toHaveValue('initial-value');

    // Should have Cancel and Save buttons
    await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Save' })).toBeVisible();
  });

  test('should close edit modal when clicking cancel', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Wait for secrets table
    await expect(page.locator('table')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('TEST_SECRET')).toBeVisible({ timeout: 10000 });

    // Open edit modal
    await page.getByRole('button', { name: /edit secret/i }).first().click();
    await expect(page.getByRole('heading', { name: 'Edit Secret' })).toBeVisible();

    // Click cancel
    await page.getByRole('button', { name: 'Cancel' }).click();

    // Modal should be closed
    await expect(page.getByRole('heading', { name: 'Edit Secret' })).not.toBeVisible();
  });

  test('should edit a secret successfully', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Wait for secrets table
    await expect(page.locator('table')).toBeVisible({ timeout: 10000 });
    await expect(page.getByText('TEST_SECRET')).toBeVisible({ timeout: 10000 });

    // Open edit modal
    await page.getByRole('button', { name: /edit secret/i }).first().click();
    await expect(page.getByRole('heading', { name: 'Edit Secret' })).toBeVisible();

    // Clear and type new value
    const valueTextarea = page.locator('textarea');
    await valueTextarea.clear();
    await valueTextarea.fill('updated-value-from-ui');

    // Click save
    await page.getByRole('button', { name: 'Save' }).click();

    // Modal should close
    await expect(page.getByRole('heading', { name: 'Edit Secret' })).not.toBeVisible({ timeout: 10000 });

    // Toggle visibility to see the new value
    await page.getByRole('button', { name: /toggle visibility/i }).first().click();

    // Should show the updated value
    await expect(page.getByText('updated-value-from-ui')).toBeVisible();
  });

  test('should add a new secret', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Click Add Secret button (the one in the header, not in modal)
    await page.locator('button:has-text("Add Secret")').first().click();

    // Add Secret modal should appear
    await expect(page.getByRole('heading', { name: 'Add Secret' })).toBeVisible();

    // Fill in the form
    await page.getByPlaceholder('DATABASE_URL').fill('NEW_SECRET_KEY');
    await page.getByPlaceholder('Enter secret value').fill('new-secret-value');

    // Click the submit button inside the modal form
    await page.locator('.modal-box button[type="submit"]').click();

    // Modal should close
    await expect(page.getByRole('heading', { name: 'Add Secret' })).not.toBeVisible({ timeout: 10000 });

    // New secret should appear in the list
    await expect(page.getByText('NEW_SECRET_KEY')).toBeVisible({ timeout: 10000 });
  });

  test('should delete a secret', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // First add a secret to delete
    await page.locator('button:has-text("Add Secret")').first().click();
    await page.getByPlaceholder('DATABASE_URL').fill('TO_DELETE');
    await page.getByPlaceholder('Enter secret value').fill('delete-me');
    await page.locator('.modal-box button[type="submit"]').click();
    await expect(page.getByRole('heading', { name: 'Add Secret' })).not.toBeVisible({ timeout: 10000 });

    // Verify it was added
    await expect(page.getByText('TO_DELETE')).toBeVisible({ timeout: 10000 });

    // Find the row with TO_DELETE and click its delete button
    const row = page.locator('tr', { has: page.getByText('TO_DELETE') });
    await row.getByRole('button', { name: /delete secret/i }).click();

    // Secret should be removed from the list
    await expect(page.getByText('TO_DELETE')).not.toBeVisible({ timeout: 5000 });
  });
});

test.describe('Secrets Page - Navigation', () => {
  test('should show breadcrumb navigation', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Should show breadcrumb with workspace, project, and environment
    // Use the breadcrumb nav specifically to avoid matching sidebar
    const breadcrumb = page.locator('.breadcrumbs');
    await expect(breadcrumb.getByRole('link', { name: 'Workspaces' })).toBeVisible();
    await expect(breadcrumb.getByRole('link', { name: workspaceName })).toBeVisible();
    await expect(breadcrumb.getByRole('link', { name: projectName })).toBeVisible();
    await expect(breadcrumb.getByText(environmentName)).toBeVisible();
  });

  test('should navigate back to project via breadcrumb', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}/environments/${environmentName}`);
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();

    // Click on project in breadcrumb
    const breadcrumb = page.locator('.breadcrumbs');
    await breadcrumb.getByRole('link', { name: projectName }).click();

    // Should be on environments page
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();
  });
});
