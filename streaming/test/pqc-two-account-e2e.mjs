import { chromium } from 'playwright';
import { mkdir } from 'node:fs/promises';

const baseUrl = process.env.PQC_TEST_BASE_URL ?? 'http://localhost:3000';
const password = process.env.PQC_TEST_PASSWORD;
const passphrase = process.env.PQC_TEST_RECOVERY_PASSPHRASE ?? 'Capstone-PQC-Recovery-2026!';
const cipherSuiteId = process.env.PQC_TEST_CIPHERSUITE_ID;
const aliceEmail = process.env.PQC_TEST_ALICE_EMAIL;
const bobEmail = process.env.PQC_TEST_BOB_EMAIL;
if (!password || !aliceEmail || !bobEmail) throw new Error('Set PQC_TEST_PASSWORD, PQC_TEST_ALICE_EMAIL and PQC_TEST_BOB_EMAIL');

const profileRoot = process.env.PQC_TEST_PROFILE_ROOT ?? '/tmp/mastodon-pqc-two-account';
await mkdir(profileRoot, { recursive: true });
const contexts = [];
const attachDiagnostics = (page, label) => {
  page.on('pageerror', (error) => console.error(`${label}_PAGE_ERROR`, error.message));
  page.on('console', (message) => { if (message.type() === 'error') console.error(`${label}_CONSOLE_ERROR`, message.text()); });
  page.on('response', async (response) => {
    if (response.url().includes('/api/v1/pqc_conversations/') && response.url().endsWith('/messages')) {
      const payload = await response.json().catch(() => null);
      const summary = Array.isArray(payload) ? payload.map(({ id, recipient_device_id: recipient }) => ({ id, recipient })) : payload && { id: payload.id };
      console.log(`${label}_MESSAGE_RELAY`, response.request().method(), response.status(), summary);
    }
    if (response.status() >= 400) console.error(`${label}_HTTP_ERROR`, response.status(), response.url(), (await response.text().catch(() => '')).slice(0, 1000));
  });
};

const signIn = async (email) => {
  const accountName = email.split('@')[0];
  const context = await chromium.launchPersistentContext(`${profileRoot}/${accountName}`, { headless: true });
  contexts.push(context);
  await context.clearCookies();
  const page = await context.newPage();
  attachDiagnostics(page, email.split('@')[0].toUpperCase());
  await page.goto(`${baseUrl}/auth/sign_in`, { waitUntil: 'domcontentloaded', timeout: 60000 });
  await page.locator('input[name="user[email]"]').fill(email);
  await page.locator('input[name="user[password]"]').fill(password);
  await page.locator('button[type="submit"]').click();
  try {
    await page.waitForURL(`${baseUrl}/`, { timeout: 30000, waitUntil: 'domcontentloaded' });
  } catch (error) {
    console.error(`${accountName.toUpperCase()}_LOGIN_STATE`, page.url(), (await page.locator('body').innerText().catch(() => '')).slice(0, 2000));
    throw error;
  }
  await page.goto(`${baseUrl}/pqc`, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.getByRole('heading', { name: 'Experimental encrypted messaging' }).waitFor({ timeout: 120000 });
  return { context, page };
};

const registerDevice = async (page, expectedMinimum) => {
  if (cipherSuiteId) await page.locator('#pqc-new-device-suite').selectOption(cipherSuiteId);
  await page.locator('#pqc-recovery-passphrase').fill(passphrase);
  const register = page.getByRole('button', { name: 'Register this browser as a device' });
  if (await register.isVisible()) {
    const registered = page.waitForResponse((response) => response.request().method() === 'POST' && response.url().includes('/api/v1/pqc_devices'), { timeout: 120000 });
    await register.click();
    const response = await registered;
    if (!response.ok()) throw new Error(`Device registration failed: ${response.status()} ${await response.text()}`);
    await page.getByRole('button', { name: 'Lock this device' }).waitFor({ timeout: 120000 });
  } else {
    const unlock = page.getByRole('button', { name: 'Unlock saved device' });
    if (await unlock.isVisible()) {
      await unlock.click();
      await page.getByRole('button', { name: 'Lock this device' }).waitFor({ timeout: 120000 });
    }
  }
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await page.getByText(new RegExp(`^[${expectedMinimum}-9] device\\(s\\) registered on this account\\.$`)).waitFor({ timeout: 30000 });
  const id = await page.evaluate(() => {
    const initial = document.querySelector('#initial-state')?.textContent;
    if (!initial) throw new Error('Mastodon initial state not found');
    return JSON.parse(initial).meta.me;
  });
  console.log('DEVICE_READY', id, 'registered-device-count-rendered');
  return String(id);
};

try {
  const alice = await signIn(aliceEmail);
  const bob = await signIn(bobEmail);
  const aliceId = await registerDevice(alice.page, 1);
  const bobId = await registerDevice(bob.page, 1);
  if (cipherSuiteId) console.log('MLS_CIPHERSUITE_SELECTED', `0x${Number(cipherSuiteId).toString(16)}`);
  if (aliceId === bobId) throw new Error('The test accounts resolved to the same account ID');
  console.log('ACCOUNTS', { aliceId, bobId });

  let conversationId = process.env.PQC_TEST_CONVERSATION_ID;
  if (conversationId && process.env.PQC_TEST_SKIP_CREATOR_SETUP === 'true') {
    const state = await alice.page.evaluate(async (token) => {
      const initial = JSON.parse(document.querySelector('#initial-state')?.textContent ?? '{}');
      const response = await fetch('/api/v1/pqc_conversations', { headers: { Authorization: `Bearer ${initial.meta.access_token}` } });
      if (!response.ok) throw new Error(`Conversation refresh failed: ${response.status}`);
      const conversations = await response.json();
      return conversations.find((conversation) => conversation.id === token)?.ready_at;
    }, conversationId);
    if (!state) throw new Error('The requested conversation is not active yet');
    console.log('MLS_GROUP_ALREADY_ACTIVE', conversationId);
  } else if (conversationId) {
    await alice.page.getByRole('button', { name: 'Refresh', exact: true }).click();
    const row = alice.page.getByText(conversationId, { exact: true }).locator('..');
    await row.getByRole('button').click();
    await alice.page.getByRole('heading', { name: 'Verify devices before continuing' }).waitFor({ timeout: 30000 });
    console.log('RESUMING_CONVERSATION', conversationId);
  } else {
    await alice.page.locator('#pqc-account-ids').fill(bobId);
    const createdResponse = alice.page.waitForResponse((response) => response.request().method() === 'POST' && response.url().includes('/api/v1/pqc_conversations'), { timeout: 30000 });
    await alice.page.getByRole('button', { name: 'Create conversation' }).click();
    const created = await createdResponse;
    if (!created.ok()) throw new Error(`Conversation creation failed: ${created.status()} ${await created.text()}`);
    conversationId = (await created.json()).id;
    await alice.page.getByRole('heading', { name: 'Waiting for invitees' }).waitFor({ timeout: 30000 });
    console.log('CONVERSATION_CREATED', { conversationId });

    await bob.page.getByRole('button', { name: 'Refresh', exact: true }).click();
    const bobConversation = bob.page.getByText(conversationId, { exact: true }).locator('..');
    const bobReview = bobConversation.getByRole('button', { name: 'Review / join' });
    await bobReview.waitFor({ timeout: 30000 });
    await bobReview.click();
    await bob.page.getByRole('button', { name: 'Accept invitation' }).click();
    await bob.page.getByRole('heading', { name: 'Waiting for group setup' }).waitFor({ timeout: 30000 });

    await alice.page.getByRole('button', { name: 'Refresh invitation status' }).click();
    await alice.page.getByRole('heading', { name: 'Verify devices before continuing' }).waitFor({ timeout: 30000 });
  }
  if (process.env.PQC_TEST_SKIP_CREATOR_SETUP !== 'true') {
    const fingerprints = await alice.page.locator('#pqc-verification-title').locator('..').innerText();
    console.log('FINGERPRINTS_PRESENT_FOR_REVIEW', fingerprints.includes('Account') && fingerprints.includes('device'));
    await alice.page.getByRole('checkbox', { name: 'I verified these fingerprints out of band' }).check();
    const setupResponse = alice.page.waitForResponse((response) => response.request().method() === 'POST' && response.url().includes(`/api/v1/pqc_conversations/${encodeURIComponent(conversationId)}/complete_setup`), { timeout: 120000 });
    await alice.page.getByRole('button', { name: /Start encrypted group|Continue encrypted group setup/ }).click();
    const completedSetup = await setupResponse;
    if (!completedSetup.ok()) throw new Error(`MLS setup failed: ${completedSetup.status()} ${await completedSetup.text()}`);
    await alice.page.getByRole('heading', { name: /Conversation/ }).waitFor({ timeout: 120000 });
    await alice.page.getByRole('button', { name: 'Encrypt and send' }).waitFor({ timeout: 120000 });
    const setupState = await alice.page.evaluate(async (token) => {
      const initial = JSON.parse(document.querySelector('#initial-state')?.textContent ?? '{}');
      const response = await fetch('/api/v1/pqc_conversations', { headers: { Authorization: `Bearer ${initial.meta.access_token}` } });
      if (!response.ok) throw new Error(`Conversation verification failed: ${response.status}`);
      const conversations = await response.json();
      return conversations.find((conversation) => conversation.id === token)?.ready_at;
    }, conversationId);
    if (!setupState) {
      const setupError = await alice.page.getByRole('alert').allInnerTexts();
      throw new Error(`The UI opened a local group state but the server did not activate it${setupError.length ? `: ${setupError.join(' ')}` : ''}`);
    }
    console.log('MLS_GROUP_STARTED');
  }

  const bobRefresh = bob.page.waitForResponse((response) => response.request().method() === 'GET' && response.url().includes('/api/v1/pqc_conversations'), { timeout: 30000 });
  await bob.page.getByRole('button', { name: 'Refresh', exact: true }).click();
  const refreshedConversations = await bobRefresh;
  const readyConversation = (await refreshedConversations.json()).find((conversation) => conversation.id === conversationId);
  if (!readyConversation?.ready_at) throw new Error('Bob did not receive the active conversation state');
  await bob.page.waitForTimeout(500);
  await bob.page.getByText(conversationId, { exact: true }).locator('..').getByRole('button', { name: /Resume|Review \/ join/ }).click();
  const verificationHeading = bob.page.getByRole('heading', { name: 'Verify devices before continuing' });
  if (await verificationHeading.isVisible()) {
    await bob.page.getByRole('checkbox', { name: 'I verified these fingerprints out of band' }).check();
    await bob.page.getByRole('button', { name: 'Join encrypted group' }).click();
  }
  const initialReceiveButton = bob.page.getByRole('button', { name: 'Receive new messages' });
  await initialReceiveButton.waitFor({ timeout: 30000 });
  await initialReceiveButton.click();
  await bob.page.waitForFunction(() => {
    const button = [...document.querySelectorAll('button')].find((element) => element.textContent?.trim() === 'Receive new messages');
    return button && !button.disabled;
  }, { timeout: 60000 });
  const joinError = await bob.page.getByRole('alert').allInnerTexts();
  if (joinError.length > 0) throw new Error(`Bob could not consume the MLS Welcome: ${joinError.join(' ')}`);
  await bob.page.getByRole('button', { name: 'Encrypt and send' }).waitFor({ state: 'visible', timeout: 30000 });
  console.log('BOB_JOINED_MLS_GROUP');

  const plaintext = `PQC two-account test ${new Date().toISOString()}`;
  const aliceConversationHeading = alice.page.getByRole('heading', { name: `Conversation ${conversationId}` });
  if (!(await aliceConversationHeading.isVisible())) {
    await alice.page.getByText(conversationId, { exact: true }).locator('..').getByRole('button', { name: /Resume|Review \/ join/ }).click();
    const aliceVerificationHeading = alice.page.getByRole('heading', { name: 'Verify devices before continuing' });
    if (await aliceVerificationHeading.isVisible()) {
      await alice.page.getByRole('checkbox', { name: 'I verified these fingerprints out of band' }).check();
      await alice.page.getByRole('button', { name: 'Join encrypted group' }).click();
    }
  }
  await aliceConversationHeading.waitFor({ timeout: 30000 });
  await bob.page.locator('#pqc-message-draft').fill('Bob join verification');
  await bob.page.waitForFunction(() => {
    const button = [...document.querySelectorAll('button')].find((element) => element.textContent?.trim() === 'Encrypt and send');
    return button && !button.disabled;
  }, { timeout: 30000 });
  await bob.page.locator('#pqc-message-draft').fill('');
  await alice.page.locator('#pqc-message-draft').fill(plaintext);
  await alice.page.waitForFunction(() => {
    const button = [...document.querySelectorAll('button')].find((element) => element.textContent?.trim() === 'Encrypt and send');
    return button && !button.disabled;
  }, { timeout: 30000 });
  const sentResponse = alice.page.waitForResponse((response) => response.request().method() === 'POST' && response.url().includes('/api/v1/pqc_conversations/') && response.url().endsWith('/messages'), { timeout: 30000 });
  await alice.page.getByRole('button', { name: 'Encrypt and send' }).click();
  const sentRelayMessage = await sentResponse;
  if (!sentRelayMessage.ok()) throw new Error(`Alice could not relay the encrypted message: ${sentRelayMessage.status()} ${await sentRelayMessage.text()}`);
  await alice.page.waitForFunction((expectedPlaintext) => document.querySelector('ol[aria-live="polite"]')?.textContent?.includes(expectedPlaintext), plaintext, { timeout: 60000 });
  console.log('ALICE_SENT_ENCRYPTED_MESSAGE');

  // Bob already has the joined group open. Reopening its list row can switch
  // the UI back into fingerprint review and discard the active view.
  await bob.page.getByRole('button', { name: 'Encrypt and send' }).waitFor({ timeout: 30000 });
  const receiveButton = bob.page.getByRole('button', { name: 'Receive new messages' });
  const receivedRelayResponse = bob.page.waitForResponse((response) => response.request().method() === 'GET' && response.url().includes('/api/v1/pqc_conversations/') && response.url().includes('/messages?'), { timeout: 30000 });
  await receiveButton.click();
  const receivedRelay = await receivedRelayResponse;
  if (!receivedRelay.ok()) throw new Error(`Bob could not fetch encrypted messages: ${receivedRelay.status()} ${await receivedRelay.text()}`);
  const receivedRelayMessages = await receivedRelay.json();
  console.log('BOB_RELAY_MESSAGE_IDS', receivedRelayMessages.map(({ id, recipient_device_id: recipient }) => ({ id, recipient })));
  if (!receivedRelayMessages.length) throw new Error('The relay returned no messages for Bob after Alice sent one');
  await bob.page.waitForFunction(() => {
    const button = [...document.querySelectorAll('button')].find((element) => element.textContent?.trim() === 'Receive new messages');
    return button && !button.disabled;
  }, { timeout: 60000 });
  const receiveError = await bob.page.getByRole('alert').allInnerTexts();
  if (receiveError.length > 0) throw new Error(`Bob could not process the relayed MLS message: ${receiveError.join(' ')}`);
  await bob.page.waitForFunction((expectedPlaintext) => document.querySelector('ol[aria-live="polite"]')?.textContent?.includes(expectedPlaintext), plaintext, { timeout: 60000 });
  console.log('BOB_DECRYPTED_MESSAGE', plaintext);
} finally {
  await Promise.all(contexts.map((context) => context.close()));
}
