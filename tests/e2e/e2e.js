const { chromium } = require('playwright');

const BASE = 'https://localhost:8443';
const SESSION = '__Host-v_session';
const results = [];
const check = (name, pass, detail='') => { results.push({name, pass, detail}); 
  console.log(`${pass?'PASS':'FAIL'}  ${name}${detail?'  — '+detail:''}`); };

(async () => {
  const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
  const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await ctx.newPage();

  // Collect anything the browser refuses to run — a CSP that blocks the page's
  // own inline scripts would break sign-in silently.
  const csp = [], errs = [];
  page.on('console', m => { if (m.type()==='error') errs.push(m.text()); });
  page.on('pageerror', e => errs.push('pageerror: '+e.message));
  page.on('response', async r => { if (r.status()>=400) csp.push(`${r.status()} ${r.url()}`); });

  // Real browser WebAuthn via CDP virtual authenticator.
  const client = await ctx.newCDPSession(page);
  await client.send('WebAuthn.enable');
  const { authenticatorId } = await client.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol:'ctap2', transport:'internal', hasResidentKey:true,
               hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true },
  });

  // ---- 1. bootstrap page ----
  await page.goto(BASE + '/', { waitUntil:'networkidle' });
  const btn = page.locator('#primary');
  await btn.waitFor({ timeout: 10000 });
  check('sign-in page offers bootstrap', (await btn.textContent()).includes('Create account'));
  check('no console errors on login page', errs.length===0, errs.join(' | '));
  check('bootstrap warning shown', await page.locator('#note').isVisible());

  // ---- 2. enroll ----
  errs.length = 0;
  await btn.click();
  await page.waitForFunction(() => !!document.getElementById('rows'), null, { timeout: 15000 })
    .catch(()=>{});
  const onDash = await page.locator('#rows').count() > 0;
  check('enrollment lands on dashboard', onDash,
        onDash ? '' : 'err=' + (await page.locator('#err').textContent().catch(()=>'?')));

  // ---- 3. the __Host- cookie actually stuck ----
  const cookies = await ctx.cookies();
  const sc = cookies.find(c => c.name === SESSION);
  check('__Host- session cookie accepted by browser', !!sc,
        sc ? `secure=${sc.secure} httpOnly=${sc.httpOnly} path=${sc.path} sameSite=${sc.sameSite}` :
             'cookies: ' + cookies.map(c=>c.name).join(','));
  if (sc) {
    check('cookie flags correct', sc.secure && sc.httpOnly && sc.path==='/' && !sc.domain.startsWith('.'),
          `secure=${sc.secure} httpOnly=${sc.httpOnly} path=${sc.path} domain=${sc.domain}`);
  }

  // ---- 4. dashboard actually renders live data (CSP would break this) ----
  await page.waitForFunction(() => {
    const h = document.getElementById('host');
    return h && h.textContent && h.textContent !== '—';
  }, null, { timeout: 15000 }).catch(()=>{});
  const host = await page.locator('#host').textContent();
  check('dashboard renders live host data', !!host && host !== '—', `host=${host}`);
  const verdict = await page.locator('#vtxt').textContent();
  check('verdict populated', verdict !== 'checking…', `verdict=${verdict}`);
  check('no console errors on dashboard', errs.length===0, errs.slice(0,3).join(' | '));

  // ---- 4b. Docker unreachable must NOT render as healthy ----
  const bannerOn = await page.locator('#banner').isVisible().catch(()=>false);
  const dockerDown = await page.evaluate(async () =>
    !!(await (await fetch('/api/status')).json())?.docker_error);
  if (dockerDown) {
    check('docker-unreachable banner shown', bannerOn);
    check('verdict is NOT "all systems healthy" while blind',
          !(await page.locator('#vtxt').textContent()).includes('all systems healthy'),
          'verdict=' + await page.locator('#vtxt').textContent());
  } else {
    console.log('SKIP  docker reachable — blind-monitor path not exercised');
  }

  // ---- 5. authenticated API works from the browser ----
  const apiStatus = await page.evaluate(async () =>
    (await fetch('/api/status', {cache:'no-store'})).status);
  check('/api/status authorized via session cookie', apiStatus===200, `status=${apiStatus}`);
  const seriesStatus = await page.evaluate(async () => {
    const to = Math.floor(Date.now()/1000);
    return (await fetch(`/api/series?metric=host.cpu&from=${to-3600}&to=${to}`)).status;
  });
  check('/api/series authorized via session cookie', seriesStatus===200, `status=${seriesStatus}`);

  // ---- 6. single-instance poll loop survives tab hide/show ----
  let reqs = 0;
  page.on('request', r => { if (r.url().includes('/api/status')) reqs++; });
  for (let i=0;i<5;i++) {
    await client.send('Emulation.setPageScaleFactor', {pageScaleFactor:1}).catch(()=>{});
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')));
    await page.waitForTimeout(200);
  }
  reqs = 0;
  await page.waitForTimeout(12000);
  check('poll loop stays single-instance after tab churn', reqs <= 4,
        `${reqs} /api/status requests in 12s (cadence 5s; >4 means duplicate chains)`);

  // ---- 7. logout is POST and clears the session ----
  // A __Host- cookie can only be deleted by a Set-Cookie that itself satisfies
  // the prefix rules; without Secure the browser drops the deletion silently.
  let logoutHdr = '';
  // Playwright omits set-cookie from headers(); allHeaders() includes it.
  const pending = [];
  const grab = r => { if (r.url().endsWith('/logout'))
    pending.push(r.allHeaders().then(h => { logoutHdr = h['set-cookie'] || logoutHdr; }).catch(()=>{})); };
  page.on('response', grab);
  await page.locator('form[action="/logout"] button').click();
  await page.waitForLoadState('networkidle');
  await Promise.all(pending);
  page.off('response', grab);
  check('logout Set-Cookie satisfies __Host- rules',
        /Secure/i.test(logoutHdr) && /Path=\//i.test(logoutHdr) && !/Domain=/i.test(logoutHdr),
        logoutHdr || '(no set-cookie)');
  await page.waitForLoadState('networkidle');
  const after = (await ctx.cookies()).find(c => c.name === SESSION);
  check('logout clears session cookie', !after);
  await page.waitForTimeout(500);
  const backToLogin = await page.locator('#primary').count() > 0;
  check('logout returns to sign-in page', backToLogin);

  // ---- 8. sign back in with the same authenticator ----
  const signIn = page.locator('#primary');
  check('sign-in offered (not bootstrap) once enrolled',
        (await signIn.textContent()).includes('Sign in'));
  await signIn.click();
  await page.waitForFunction(() => !!document.getElementById('rows'), null, { timeout: 15000 })
    .catch(()=>{});
  check('login round-trip works in a real browser', await page.locator('#rows').count() > 0);

  await client.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  await browser.close();

  const failed = results.filter(r=>!r.pass);
  console.log(`\n${results.length-failed.length}/${results.length} passed`);
  if (csp.length) console.log('4xx/5xx responses seen: ' + csp.join(', '));
  process.exit(failed.length ? 1 : 0);
})().catch(e => { console.error('HARNESS ERROR:', e); process.exit(2); });
