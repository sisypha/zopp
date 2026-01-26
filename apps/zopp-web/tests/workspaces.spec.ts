/**
 * E2E tests for workspaces, projects, and environments management.
 * Uses the authenticated fixture for full integration testing.
 *
 * Note: The workspaces listing page was removed. Workspace creation is now
 * done via the sidebar dropdown. Tests navigate directly to workspace URLs.
 */

import { test, expect } from './fixtures/test-setup';

test.describe('Workspace Creation (via Sidebar)', () => {
  test('should create a new workspace from sidebar dropdown', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;
    const newWorkspaceName = `new-ws-${Date.now()}`;

    // Navigate to existing workspace (projects page)
    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Open the workspace dropdown in sidebar
    const sidebar = page.locator('aside');
    await sidebar.getByText(workspaceName).click();

    // Click "Create Workspace" in dropdown
    await sidebar.getByText('Create Workspace').click();

    // Modal should appear
    await expect(page.getByRole('heading', { name: /Create Workspace/i })).toBeVisible();

    // Fill in workspace name
    await page.getByPlaceholder(/my-workspace/i).fill(newWorkspaceName);

    // Submit
    await page.locator('[data-testid="modal-content"] button').filter({ hasText: 'Create' }).click();

    // Should navigate to the new workspace
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible({ timeout: 10000 });
    await expect(page).toHaveURL(new RegExp(`/workspaces/${newWorkspaceName}`));
  });

  test('should create workspace, project, environment, and secret from web UI', async ({ authenticatedPage, testContext }) => {
    // This test verifies the full flow using only web UI operations.
    // It specifically tests that KEK wrapping/unwrapping works correctly
    // (regression test for AAD mismatch bug where workspace name was used
    // during wrap but workspace ID was used during unwrap).
    const page = authenticatedPage;
    const { workspaceName } = testContext;
    const testId = Date.now();
    const wsName = `web-ws-${testId}`;
    const projName = `web-proj-${testId}`;
    const envName = `web-env-${testId}`;
    const secretKey = `WEB_SECRET_${testId}`;
    const secretValue = `secret-value-${testId}`;

    // Step 1: Create workspace from sidebar dropdown
    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Open workspace dropdown
    const sidebar = page.locator('aside');
    await sidebar.getByText(workspaceName).click();
    await sidebar.getByText('Create Workspace').click();

    // Fill in and create workspace
    await expect(page.getByRole('heading', { name: /Create Workspace/i })).toBeVisible();
    await page.getByPlaceholder(/my-workspace/i).fill(wsName);
    await page.locator('[data-testid="modal-content"] button').filter({ hasText: 'Create' }).click();

    // Should navigate to new workspace projects page
    await expect(page).toHaveURL(new RegExp(`/workspaces/${wsName}`), { timeout: 15000 });
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Step 2: Create project
    await page.getByRole('button', { name: /Create Project/i }).click();
    await expect(page.getByRole('heading', { name: /Create Project/i })).toBeVisible();
    await page.getByPlaceholder(/my-project/i).fill(projName);
    await page.locator('[data-testid="modal-content"] button[type="submit"]').click();
    await expect(page.getByText(projName)).toBeVisible({ timeout: 15000 });

    // Step 3: Navigate to project and create environment
    // This step tests KEK unwrapping - if AAD mismatches, this will fail
    await page.getByRole('link', { name: projName }).click();
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Create Environment/i }).click();
    await expect(page.getByRole('heading', { name: /Create Environment/i })).toBeVisible();
    await page.getByPlaceholder(/production/i).fill(envName);
    await page.locator('[data-testid="modal-content"] button[type="submit"]').click();

    // Verify no error appears and environment is created
    await expect(page.locator('[data-testid="error-alert"]')).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByText(envName)).toBeVisible({ timeout: 15000 });

    // Step 4: Navigate to environment and create a secret
    // This tests full DEK encryption/decryption
    await page.getByRole('link', { name: envName }).click();
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Add.*Secret/i }).click();
    await expect(page.getByRole('heading', { name: /Add Secret/i })).toBeVisible();
    await page.getByPlaceholder(/DATABASE_URL/i).fill(secretKey);
    await page.getByPlaceholder(/Enter secret value/i).fill(secretValue);
    await page.locator('[data-testid="modal-content"] button[type="submit"]').click();

    // Verify no error and secret appears
    await expect(page.locator('[data-testid="error-alert"]')).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByText(secretKey)).toBeVisible({ timeout: 15000 });

    // Step 5: Verify we can read the secret back (tests decryption)
    await page.locator('button[title="Toggle visibility"]').first().click();
    await expect(page.getByText(secretValue)).toBeVisible({ timeout: 5000 });
  });

  test('should switch between workspaces via dropdown', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;
    const newWorkspaceName = `switch-ws-${Date.now()}`;

    // Navigate to existing workspace
    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Create a second workspace
    const sidebar = page.locator('aside');
    await sidebar.getByText(workspaceName).click();
    await sidebar.getByText('Create Workspace').click();
    await page.getByPlaceholder(/my-workspace/i).fill(newWorkspaceName);
    await page.locator('[data-testid="modal-content"] button').filter({ hasText: 'Create' }).click();

    // Should be on new workspace now
    await expect(page).toHaveURL(new RegExp(`/workspaces/${newWorkspaceName}`), { timeout: 10000 });

    // Open dropdown and switch back to original workspace
    await sidebar.getByText(newWorkspaceName).click();
    await sidebar.getByRole('button', { name: workspaceName }).click();

    // Should navigate to original workspace
    await expect(page).toHaveURL(new RegExp(`/workspaces/${workspaceName}`), { timeout: 10000 });
  });
});

test.describe('Projects Page', () => {
  test('should show projects page with existing project', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);

    // Should show the projects heading
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Should have create project button
    await expect(page.getByRole('button', { name: /Create Project/i })).toBeVisible();

    // Should show breadcrumb with workspace name
    const breadcrumb = page.locator('[data-testid="breadcrumb"]');
    await expect(breadcrumb.getByText(workspaceName)).toBeVisible();

    // Should show our test project
    await expect(page.getByText(projectName)).toBeVisible({ timeout: 10000 });
  });

  test('should create a new project', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;
    const newProjectName = `new-proj-${Date.now()}`;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Click create project button
    await page.getByRole('button', { name: /Create Project/i }).click();

    // Modal should appear
    await expect(page.getByRole('heading', { name: /Create Project/i })).toBeVisible();

    // Fill in project name
    await page.getByPlaceholder(/my-project/i).fill(newProjectName);

    // Submit
    await page.locator('[data-testid="modal-content"] button[type="submit"]').click();

    // Modal should close
    await expect(page.getByRole('heading', { name: /Create Project/i })).not.toBeVisible({ timeout: 10000 });

    // New project should appear in the list
    await expect(page.getByText(newProjectName)).toBeVisible({ timeout: 10000 });
  });

  test('should navigate to environments page when clicking project', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Wait for project to appear
    await expect(page.getByText(projectName)).toBeVisible({ timeout: 10000 });

    // Click on project card/link
    await page.getByRole('link', { name: projectName }).click();

    // Should be on environments page
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();
  });

  test('should have invite and permissions buttons', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Should have invite button (use exact match to avoid matching sidebar "Invites")
    await expect(page.getByRole('link', { name: 'Invite', exact: true })).toBeVisible();

    // Should have permissions button (use exact match to avoid matching sidebar)
    await expect(page.getByRole('link', { name: 'Permissions', exact: true })).toBeVisible();
  });
});

test.describe('Environments Page', () => {
  test('should show environments page with existing environment', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}`);

    // Should show the environments heading
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();

    // Should have create environment button
    await expect(page.getByRole('button', { name: /Create Environment/i })).toBeVisible();

    // Should show breadcrumb with workspace link and project name
    const breadcrumb = page.locator('[data-testid="breadcrumb"]');
    await expect(breadcrumb.getByRole('link', { name: workspaceName })).toBeVisible();
    await expect(breadcrumb.getByText(projectName)).toBeVisible();

    // Should show our test environment
    await expect(page.getByText(environmentName)).toBeVisible({ timeout: 10000 });
  });

  test('should create a new environment', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName } = testContext;
    const newEnvName = `new-env-${Date.now()}`;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}`);
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();

    // Click create environment button
    await page.getByRole('button', { name: /Create Environment/i }).click();

    // Modal should appear
    await expect(page.getByRole('heading', { name: /Create Environment/i })).toBeVisible();

    // Fill in environment name
    await page.getByPlaceholder(/production/i).fill(newEnvName);

    // Submit
    await page.locator('[data-testid="modal-content"] button[type="submit"]').click();

    // Modal should close
    await expect(page.getByRole('heading', { name: /Create Environment/i })).not.toBeVisible({ timeout: 10000 });

    // New environment should appear in the list
    await expect(page.getByText(newEnvName)).toBeVisible({ timeout: 10000 });
  });

  test('should navigate to secrets page when clicking environment', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName, projectName, environmentName } = testContext;

    await page.goto(`/workspaces/${workspaceName}/projects/${projectName}`);
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();

    // Wait for environment to appear
    await expect(page.getByText(environmentName)).toBeVisible({ timeout: 10000 });

    // Click on environment card/link
    await page.getByRole('link', { name: environmentName }).click();

    // Should be on secrets page
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();
  });
});

test.describe('Dashboard Navigation', () => {
  test('should have working sidebar navigation', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Sidebar should have key links
    const sidebar = page.locator('aside');
    await expect(sidebar.getByRole('link', { name: /Projects/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Settings/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Permissions/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Invites/i })).toBeVisible();
  });

  test('should navigate to settings from sidebar', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto(`/workspaces/${workspaceName}`);
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();

    // Click settings in sidebar
    const sidebar = page.locator('aside');
    await sidebar.getByRole('link', { name: /Settings/i }).click();

    // Should be on settings page
    await expect(page.getByRole('heading', { name: /Settings/i })).toBeVisible();
  });
});
