import { defineConfig, devices } from '@playwright/test';

const PORT = 4273;
const BASE = '/crypto-lab-phantom-vault/';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 90_000,
  reporter: 'list',
  use: {
    baseURL: `http://localhost:${PORT}${BASE}`,
    colorScheme: 'dark',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    command: `npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}${BASE}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
