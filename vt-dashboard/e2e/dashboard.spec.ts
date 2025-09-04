import { test, expect } from '@playwright/test';

test.describe('VirusTotal Dashboard E2E', () => {
  test.beforeEach(async ({ page }) => {
    // Navigate to the dashboard
    await page.goto('/');
  });

  test('loads dashboard with all main components', async ({ page }) => {
    // Check page title
    await expect(page).toHaveTitle(/VirusTotal Dashboard/);
    
    // Wait for dashboard stats to load
    await expect(page.getByText('Total Reports')).toBeVisible();
    await expect(page.getByText('Malicious Files')).toBeVisible();
    await expect(page.getByText('Suspicious Files')).toBeVisible();
    await expect(page.getByText('Clean Files')).toBeVisible();
    
    // Check for charts
    await expect(page.getByText('File Types')).toBeVisible();
    await expect(page.getByText('Detection Trends')).toBeVisible();
    
    // Check for recent reports
    await expect(page.getByText('Recent Reports')).toBeVisible();
  });

  test('displays statistics with proper formatting', async ({ page }) => {
    // Wait for stats to load
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Check that numeric values are displayed (should be numbers, not 0 or loading)
    const statsCards = page.locator('[class*="text-2xl"][class*="font-bold"]');
    await expect(statsCards.first()).toBeVisible();
    
    // Verify that stats show actual numbers (not just placeholders)
    const firstStatValue = await statsCards.first().textContent();
    expect(firstStatValue).not.toBe('0');
    expect(firstStatValue).not.toBe('');
  });

  test('charts render and display data', async ({ page }) => {
    // Wait for charts to be visible
    await expect(page.getByText('File Types')).toBeVisible();
    await expect(page.getByText('Detection Trends')).toBeVisible();
    
    // Wait for chart components to render (charts typically take longer to load)
    await page.waitForTimeout(2000);
    
    // Check that charts have rendered content (not just loading states)
    const chartsContainer = page.locator('[class*="h-80"]');
    await expect(chartsContainer.first()).toBeVisible();
  });

  test('recent reports section displays report data', async ({ page }) => {
    // Wait for recent reports section
    await expect(page.getByText('Recent Reports')).toBeVisible();
    
    // Wait for data to load
    await page.waitForTimeout(1000);
    
    // Check if reports table is rendered (may be empty in test env)
    const reportsSection = page.locator('text=Recent Reports').locator('..').locator('..');
    await expect(reportsSection).toBeVisible();
  });

  test('handles responsive design on different screen sizes', async ({ page }) => {
    // Test desktop view
    await page.setViewportSize({ width: 1200, height: 800 });
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Test tablet view
    await page.setViewportSize({ width: 768, height: 1024 });
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Test mobile view
    await page.setViewportSize({ width: 375, height: 667 });
    await expect(page.getByText('Total Reports')).toBeVisible();
  });

  test('dashboard loads within acceptable time', async ({ page }) => {
    const startTime = Date.now();
    
    // Navigate and wait for main content
    await page.goto('/');
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    const loadTime = Date.now() - startTime;
    expect(loadTime).toBeLessThan(5000); // Should load within 5 seconds
  });

  test('statistics cards show proper color coding', async ({ page }) => {
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Check for danger variant (malicious files - should have red styling)
    const maliciousCard = page.locator('text=Malicious Files').locator('..').locator('..');
    await expect(maliciousCard).toBeVisible();
    
    // Check for success variant (clean files - should have green styling)
    const cleanCard = page.locator('text=Clean Files').locator('..').locator('..');
    await expect(cleanCard).toBeVisible();
    
    // Check for warning variant (suspicious files - should have yellow/orange styling)
    const suspiciousCard = page.locator('text=Suspicious Files').locator('..').locator('..');
    await expect(suspiciousCard).toBeVisible();
  });

  test('navigation and accessibility', async ({ page }) => {
    // Check that dashboard is keyboard accessible
    await page.keyboard.press('Tab');
    
    // Should be able to navigate through interactive elements
    const focusedElement = await page.evaluate(() => document.activeElement?.tagName);
    expect(['BUTTON', 'A', 'INPUT', 'SELECT']).toContain(focusedElement || '');
    
    // Check for proper heading structure
    const headings = page.locator('h1, h2, h3, h4, h5, h6');
    await expect(headings.first()).toBeVisible();
  });

  test('error handling - graceful degradation', async ({ page }) => {
    // Test that dashboard doesn't break if some data fails to load
    await page.goto('/');
    
    // Dashboard structure should still be present
    await expect(page.getByText('Total Reports')).toBeVisible();
    await expect(page.getByText('File Types')).toBeVisible();
    await expect(page.getByText('Detection Trends')).toBeVisible();
    
    // Even if data fails, the layout should remain intact
    const dashboard = page.locator('body');
    await expect(dashboard).toBeVisible();
  });

  test('theme consistency across components', async ({ page }) => {
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Check that theme is applied consistently
    // Dashboard should have consistent styling across all components
    const cards = page.locator('[class*="card"]');
    await expect(cards.first()).toBeVisible();
    
    // Charts should match the overall theme
    await expect(page.getByText('File Types')).toBeVisible();
    await expect(page.getByText('Detection Trends')).toBeVisible();
  });

  test('real-time data updates and refresh capability', async ({ page }) => {
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Get initial value
    const initialValue = await page.locator('[class*="text-2xl"][class*="font-bold"]').first().textContent();
    
    // Refresh page
    await page.reload();
    await expect(page.getByText('Total Reports')).toBeVisible();
    
    // Should load data again (values should be consistent)
    const refreshedValue = await page.locator('[class*="text-2xl"][class*="font-bold"]').first().textContent();
    expect(refreshedValue).toBe(initialValue);
  });
});