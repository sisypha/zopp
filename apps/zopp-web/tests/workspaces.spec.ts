/**
 * E2E tests for workspaces, projects, and environments management.
 * Uses the authenticated fixture for full integration testing.
 */

import { test, expect } from './fixtures/test-setup';

test.describe('Workspaces Page', () => {
  test('should show workspaces page with existing workspace', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto('/workspaces');

    // Should show the workspaces heading
    await expect(page.getByRole('heading', { name: 'Workspaces', exact: true })).toBeVisible();

    // Should have create workspace button
    await expect(page.getByRole('button', { name: /Create Workspace/i })).toBeVisible();

    // Should show our test workspace
    await expect(page.getByText(workspaceName)).toBeVisible({ timeout: 10000 });
  });

  test('should create a new workspace', async ({ authenticatedPage }) => {
    const page = authenticatedPage;
    const newWorkspaceName = `new-ws-${Date.now()}`;

    await page.goto('/workspaces');
    await expect(page.getByRole('heading', { name: 'Workspaces', exact: true })).toBeVisible();

    // Click create workspace button
    await page.getByRole('button', { name: /Create Workspace/i }).click();

    // Modal should appear
    await expect(page.getByRole('heading', { name: /Create Workspace/i })).toBeVisible();

    // Fill in workspace name
    await page.getByPlaceholder(/my-workspace/i).fill(newWorkspaceName);

    // Submit
    await page.locator('.modal-box button[type="submit"]').click();

    // Modal should close
    await expect(page.getByRole('heading', { name: /Create Workspace/i })).not.toBeVisible({ timeout: 10000 });

    // New workspace should appear in the list
    await expect(page.getByText(newWorkspaceName)).toBeVisible({ timeout: 10000 });
  });

  test('should create workspace, project, environment, and secret from web UI', async ({ authenticatedPage }) => {
    // This test verifies the full flow using only web UI operations.
    // It specifically tests that KEK wrapping/unwrapping works correctly
    // (regression test for AAD mismatch bug where workspace name was used
    // during wrap but workspace ID was used during unwrap).
    const page = authenticatedPage;
    const testId = Date.now();
    const wsName = `web-ws-${testId}`;
    const projName = `web-proj-${testId}`;
    const envName = `web-env-${testId}`;
    const secretKey = `WEB_SECRET_${testId}`;
    const secretValue = `secret-value-${testId}`;

    // Step 1: Create workspace from web UI
    await page.goto('/workspaces');
    await expect(page.getByRole('heading', { name: 'Workspaces', exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Create Workspace/i }).click();
    await expect(page.getByRole('heading', { name: /Create Workspace/i })).toBeVisible();
    await page.getByPlaceholder(/my-workspace/i).fill(wsName);
    await page.locator('.modal-box button[type="submit"]').click();
    await expect(page.getByText(wsName)).toBeVisible({ timeout: 15000 });

    // Step 2: Navigate to workspace and create project
    await page.getByRole('link', { name: wsName }).click();
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Create Project/i }).click();
    await expect(page.getByRole('heading', { name: /Create Project/i })).toBeVisible();
    await page.getByPlaceholder(/my-project/i).fill(projName);
    await page.locator('.modal-box button[type="submit"]').click();
    await expect(page.getByText(projName)).toBeVisible({ timeout: 15000 });

    // Step 3: Navigate to project and create environment
    // This step tests KEK unwrapping - if AAD mismatches, this will fail
    await page.getByRole('link', { name: projName }).click();
    await expect(page.getByRole('heading', { name: 'Environments', exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Create Environment/i }).click();
    await expect(page.getByRole('heading', { name: /Create Environment/i })).toBeVisible();
    await page.getByPlaceholder(/production/i).fill(envName);
    await page.locator('.modal-box button[type="submit"]').click();

    // Verify no error appears and environment is created
    await expect(page.locator('.alert-error')).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByText(envName)).toBeVisible({ timeout: 15000 });

    // Step 4: Navigate to environment and create a secret
    // This tests full DEK encryption/decryption
    await page.getByRole('link', { name: envName }).click();
    await expect(page.getByRole('heading', { name: 'Secrets', exact: true })).toBeVisible();
    await page.getByRole('button', { name: /Add.*Secret/i }).click();
    await expect(page.getByRole('heading', { name: /Add Secret/i })).toBeVisible();
    await page.getByPlaceholder(/DATABASE_URL/i).fill(secretKey);
    await page.getByPlaceholder(/Enter secret value/i).fill(secretValue);
    await page.locator('.modal-box button[type="submit"]').click();

    // Verify no error and secret appears
    await expect(page.locator('.alert-error')).not.toBeVisible({ timeout: 5000 });
    await expect(page.getByText(secretKey)).toBeVisible({ timeout: 15000 });

    // Step 5: Verify we can read the secret back (tests decryption)
    await page.getByRole('button', { name: /Show/i }).first().click();
    await expect(page.getByText(secretValue)).toBeVisible({ timeout: 5000 });
  });

  test('should navigate to projects page when clicking workspace', async ({ authenticatedPage, testContext }) => {
    const page = authenticatedPage;
    const { workspaceName } = testContext;

    await page.goto('/workspaces');
    await expect(page.getByRole('heading', { name: 'Workspaces', exact: true })).toBeVisible();

    // Wait for workspace to appear
    await expect(page.getByText(workspaceName)).toBeVisible({ timeout: 10000 });

    // Click on workspace card/link
    await page.getByRole('link', { name: workspaceName }).click();

    // Should be on projects page
    await expect(page.getByRole('heading', { name: 'Projects', exact: true })).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/workspaces/${workspaceName}`));
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

    // Should show breadcrumb
    const breadcrumb = page.locator('.breadcrumbs');
    await expect(breadcrumb.getByRole('link', { name: 'Workspaces' })).toBeVisible();
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
    await page.locator('.modal-box button[type="submit"]').click();

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

    // Should have invite button
    await expect(page.getByRole('link', { name: /Invite/i })).toBeVisible();

    // Should have permissions button
    await expect(page.getByRole('link', { name: /Permissions/i })).toBeVisible();
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

    // Should show breadcrumb
    const breadcrumb = page.locator('.breadcrumbs');
    await expect(breadcrumb.getByRole('link', { name: 'Workspaces' })).toBeVisible();
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
    await page.locator('.modal-box button[type="submit"]').click();

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
  test('should have working sidebar navigation', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/workspaces');
    await expect(page.getByRole('heading', { name: 'Workspaces', exact: true })).toBeVisible();

    // Sidebar should have key links
    const sidebar = page.locator('aside, .drawer-side');
    await expect(sidebar.getByRole('link', { name: /Workspaces/i })).toBeVisible();
    await expect(sidebar.getByRole('link', { name: /Settings/i })).toBeVisible();
  });

  test('should navigate to settings from sidebar', async ({ authenticatedPage }) => {
    const page = authenticatedPage;

    await page.goto('/workspaces');
    await expect(page.getByRole('heading', { name: 'Workspaces', exact: true })).toBeVisible();

    // Click settings in sidebar
    const sidebar = page.locator('aside, .drawer-side');
    await sidebar.getByRole('link', { name: /Settings/i }).click();

    // Should be on settings page
    await expect(page.getByRole('heading', { name: /Settings/i })).toBeVisible();
  });
});
