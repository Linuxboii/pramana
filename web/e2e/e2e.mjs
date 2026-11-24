// End-to-end browser test of the full demo against a running server.
//
//   PRAMANA_URL=http://127.0.0.1:8080 node e2e/e2e.mjs
//
// Uses playwright-core with an installed Chrome/Edge (no browser download).
// Override the browser with PRAMANA_BROWSER=/path/to/chrome. Screenshots go to
// e2e/screenshots/. Exits non-zero on the first failed expectation.
import { chromium } from 'playwright-core'
import { existsSync, mkdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const BASE = process.env.PRAMANA_URL ?? 'http://127.0.0.1:8080'
const OUT = join(dirname(fileURLToPath(import.meta.url)), 'screenshots')
mkdirSync(OUT, { recursive: true })

const candidates = [
  process.env.PRAMANA_BROWSER,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean)
const executablePath = candidates.find((p) => existsSync(p))
if (!executablePath) {
  console.error('No Chrome/Edge found; set PRAMANA_BROWSER')
  process.exit(2)
}

const results = []
function expect(cond, what) {
  results.push({ ok: !!cond, what })
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${what}`)
  if (!cond) throw new Error(`expectation failed: ${what}`)
}

const browser = await chromium.launch({ executablePath, headless: true })
const errors = []
try {
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 } })
  const page = await ctx.newPage()
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()))
  page.on('pageerror', (e) => errors.push(String(e)))
  page.setDefaultTimeout(20_000)

  await page.goto(BASE)
  await page.getByRole('heading', { name: 'Your wallet' }).waitFor()
  expect(true, 'app boots, wallet WebAssembly loads')
  await page.waitForTimeout(1800)
  await page.screenshot({ path: join(OUT, '01-hero.png') })

  // ---- Try it: honest adult
  const tryIt = page.locator('#try')
  await tryIt.getByRole('button', { name: /Request credential/ }).click()
  await tryIt.getByText(/Age credential active/).waitFor()
  expect(true, 'credential issued and self-checked in the wallet')
  await tryIt.getByRole('button', { name: 'Prove your age privately' }).click()
  await tryIt.getByText(/will learn:/).waitFor()
  expect(await tryIt.getByText(/It will\s+not learn your date of birth/).count(), 'consent screen states the ZK guarantee')
  await tryIt.getByRole('button', { name: 'Prove', exact: true }).click()
  await tryIt.getByText('Access granted').waitFor()
  expect(true, 'adult proves 18+ and the shop grants access')
  await tryIt.getByRole('button', { name: 'What the website received' }).click()
  const absent = await tryIt.getByText('Absent', { exact: true }).count()
  expect(absent === 3, `birthdate, day count and r are all absent from the proof (${absent}/3)`)
  const clipped = await page.evaluate(() =>
    [...document.querySelectorAll('#try .overflow-hidden')].some((el) => el.scrollWidth > el.clientWidth + 1),
  )
  expect(!clipped, 'shop panel content fits its frame (no clipped overflow)')
  await tryIt.screenshot({ path: join(OUT, '02-try-it-granted.png') })

  // audit log has no PII
  const audit = await (await page.request.get(`${BASE}/api/shop/audit`)).json()
  expect(audit.entries.length >= 1 && !JSON.stringify(audit).includes('2001'), 'verifier audit log holds no birthdate')

  // ---- Try it: 14-year-old
  await tryIt.getByRole('button', { name: 'Remove from wallet' }).click()
  await tryIt.getByRole('button', { name: 'A 14-year-old' }).click()
  await tryIt.getByRole('button', { name: /Request credential/ }).click()
  await tryIt.getByText(/Age credential active/).waitFor()
  await tryIt.getByRole('button', { name: 'Check again with a new challenge' }).click()
  await tryIt.getByRole('button', { name: 'Prove your age privately' }).click()
  await tryIt.getByRole('button', { name: 'Prove', exact: true }).click()
  await tryIt.getByText('No proof possible').waitFor()
  expect(true, '14-year-old: wallet cannot build an 18+ proof, sends nothing')
  // …but can prove 13+
  await tryIt.getByRole('button', { name: 'Back to the shop' }).click()
  await tryIt.getByRole('combobox').selectOption('13')
  await tryIt.getByRole('button', { name: 'Prove your age privately' }).click()
  await tryIt.getByRole('button', { name: 'Prove', exact: true }).click()
  await tryIt.getByText('Access granted').waitFor()
  expect(true, '14-year-old proves 13+')
  await tryIt.screenshot({ path: join(OUT, '03-try-it-teen.png') })

  // ---- Demonstration acts
  const demo = page.locator('#demo')
  async function runAct(tab, shot) {
    await demo.getByRole('tab', { name: tab }).click()
    await demo.getByRole('button', { name: 'Run this act' }).click()
    await demo.getByRole('button', { name: 'Run again' }).waitFor({ timeout: 30_000 })
    const badges = await demo.locator('ol[aria-live] li span.rounded-full').allInnerTexts()
    await demo.screenshot({ path: join(OUT, shot) })
    return badges.map((b) => b.trim())
  }

  let b = await runAct('The honest path', '04-act1-honest.png')
  expect(b.at(-1) === 'Accepted' && !b.includes('Error'), `act 1 honest path accepted [${b}]`)

  b = await runAct('The cheat', '05-act2-cheat.png')
  expect(b.includes('No solution') && b.filter((x) => x === 'Rejected').length === 2 && !b.includes('Accepted'), `act 2 cheats rejected [${b}]`)

  b = await runAct('The forgery attempt', '06-act3-forgery.png')
  expect(b.filter((x) => x === 'Rejected').length === 3 && !b.includes('Accepted'), `act 3 forgeries rejected [${b}]`)
  // hand-edit: untouched passes, edited fails
  await demo.getByRole('button', { name: 'Load a fresh valid proof' }).click()
  await demo.getByRole('button', { name: 'Send to the shop' }).click()
  await demo.getByText('Your edited proof').waitFor()
  const untouched = await demo.locator('li:has-text("Your edited proof") span.rounded-full').innerText()
  expect(untouched.trim() === 'Accepted', 'act 3 untouched hand-edit proof is accepted')
  await demo.getByRole('button', { name: 'Load a fresh valid proof' }).click()
  const ta = demo.locator('#proof-editor')
  const text = await ta.inputValue()
  const i = text.indexOf('"z0": "') + 8
  const flipped = text.slice(0, i) + (text[i] === 'a' ? 'b' : 'a') + text.slice(i + 1)
  await ta.fill(flipped)
  await demo.getByRole('button', { name: 'Send to the shop' }).click()
  await demo.locator('li:has-text("Your edited proof") span.rounded-full:has-text("Rejected")').waitFor()
  expect(true, 'act 3 a one-character hand edit is rejected')

  b = await runAct('The replay', '07-act4-replay.png')
  expect(JSON.stringify(b.filter((x) => x === 'Accepted' || x === 'Rejected')) === JSON.stringify(['Rejected', 'Rejected', 'Accepted', 'Rejected']), `act 4 replay sequence [${b}]`)

  await demo.getByRole('tab', { name: 'The X-ray' }).click()
  await demo.getByRole('button', { name: 'Run this act' }).click()
  await demo.getByText('All 16 bits verify').first().waitFor({ timeout: 60_000 })
  expect((await demo.getByText('All 16 bits verify').count()) === 2, 'act 5 real and simulated transcripts both verify')
  await demo.getByRole('button', { name: 'Transcript A' }).click()
  await demo.getByText(/was the real one/).waitFor()
  expect(await demo.locator('svg[role="img"] rect').count() === 32, 'act 5 histogram drawn')
  await demo.screenshot({ path: join(OUT, '08-act5-xray.png') })

  // ---- Mobile layout
  const m = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2 })
  const mp = await m.newPage()
  await mp.goto(BASE)
  await mp.getByRole('heading', { name: 'Your wallet' }).waitFor()
  await mp.waitForTimeout(1500)
  const overflow = await mp.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(overflow <= 0, `no horizontal scroll at 390px (overflow ${overflow}px)`)
  await mp.screenshot({ path: join(OUT, '09-mobile.png'), fullPage: false })

  expect(errors.length === 0, `no console errors${errors.length ? ': ' + errors.join(' | ') : ''}`)
} catch (e) {
  console.error(String(e))
  results.push({ ok: false, what: String(e) })
} finally {
  await browser.close()
}
const failed = results.filter((r) => !r.ok)
console.log(`\n${results.length - failed.length}/${results.length} checks passed; screenshots in ${OUT}`)
process.exit(failed.length ? 1 : 0)
