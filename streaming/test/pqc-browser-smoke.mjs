import { chromium } from 'playwright';

const baseUrl = process.env.PQC_TEST_BASE_URL ?? 'http://localhost:3000';
const email = process.env.PQC_TEST_EMAIL;
const password = process.env.PQC_TEST_PASSWORD;
if (!email || !password) throw new Error('Set PQC_TEST_EMAIL and PQC_TEST_PASSWORD');

const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const pageErrors = [];
  page.on('pageerror', (error) => {
    pageErrors.push(error.message);
    console.error('PAGE_ERROR', error.message);
  });
  page.on('console', (message) => { if (message.type() === 'error') console.error('CONSOLE_ERROR', message.text()); });
  page.on('response', (response) => { if (response.status() >= 400) console.error('HTTP_ERROR', response.status(), response.url()); });
  await page.goto(`${baseUrl}/auth/sign_in`, { waitUntil: 'domcontentloaded' });
  await page.locator('input[name="user[email]"]').fill(email);
  await page.locator('input[name="user[password]"]').fill(password);
  await page.locator('button[type="submit"]').click();
  await page.waitForTimeout(3000);
  console.log('LOGIN_URL', page.url());
  console.log('LOGIN_TEXT', (await page.locator('body').innerText()).slice(0, 2000));
  await page.goto(`${baseUrl}/pqc`, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.getByRole('heading', { name: 'Experimental encrypted messaging' }).waitFor({ timeout: 60000 });
  if (process.env.PQC_TEST_SKIP_DEVICE_REGISTRATION !== 'true') {
    const passphrase = process.env.PQC_TEST_RECOVERY_PASSPHRASE ?? 'Capstone-PQC-Recovery-2026!';
    await page.locator('#pqc-recovery-passphrase').fill(passphrase);
    const registerButton = page.getByRole('button', { name: 'Register this browser as a device' });
    if (await registerButton.isVisible()) {
      await registerButton.click();
      await page.getByRole('button', { name: 'Lock this device' }).waitFor({ timeout: 60000 });
    }
  }
  await page.waitForTimeout(3000);
  console.log('URL', page.url());
  console.log('TEXT', (await page.locator('body').innerText()).slice(0, 5000));
  console.log('SCRIPTS', await page.locator('script[src]').evaluateAll((scripts) => scripts.map((script) => script.src)));
  console.log('PQC_RESOURCES', await page.evaluate(() => performance.getEntriesByType('resource').map((entry) => entry.name).filter((name) => /pqc|mls|noble/i.test(name))));
  await page.screenshot({ path: `/tmp/${email.split('@')[0]}-pqc.png`, fullPage: true });
  if (pageErrors.length > 0) throw new Error(`PQC UI page errors: ${pageErrors.join('; ')}`);
} finally {
  await browser.close();
}
