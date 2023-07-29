import { expect, test } from '@playwright/test';

test('all tests passed', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByText('Tests passed')).toBeVisible();
});
