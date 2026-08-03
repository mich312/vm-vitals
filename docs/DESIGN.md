# vitals — dashboard design system & build plan

Synthesized from a panel of design-research passes (best-in-class observability
UIs, a dark design system, data-viz craft, and information architecture). The
north star: **an instrument you trust at 3am** — calm, dense-but-legible,
premium by restraint, and honest (never fakes green when data is stale).

Constraints (non-negotiable): the UI ships as static HTML/CSS/JS **embedded in
the binary** — no CDN, no external fonts, no network beyond the app's own API.
Dark-first, theme-aware. One opinionated page (not a dashboard *builder*, not a
fleet manager) for a single host + its containers.

---

## 1. Voice (four principles)

1. **Instrument, not toy.** Cool neutrals, tabular numbers, mono for data. Zero
   decoration that isn't information.
2. **The ink is the brand.** One restrained azure accent; the UI is ~95%
   neutral. Color is *reserved for meaning*: accent = interactive; green/amber/
   red = system state. When something turns red, it matters — because nothing
   else has color.
3. **Depth through light, not noise.** On dark, elevation = lighter surface +
   1px hairline (+ a faint top rim), shadow only a whisper. No glow, no
   flair-gradients.
4. **Motion that settles.** Everything ≤240ms, decelerating into place. Numbers
   update like a readout (cross-fade + tabular-nums), never a slot machine.

**Health-color contract** (this product's subject *is* health, so green is
allowed here): `ok`=running/passing, `warn`=degraded/thresholded/unknown,
`danger`=down/broken/crit, `accent`=selection & focus only (never health).
**The greyscale test is law**: every state carries a second channel (glyph/
shape/word), so it's legible with color removed.

---

## 2. Design tokens (paste into one embedded `tokens.css`)

Dark-first `:root`; light via `@media (prefers-color-scheme: light)` and a
manual `:root[data-theme="light"]` override (the toggle stamps `data-theme`).

### Color — dark
```css
:root{
  /* backgrounds: lighter = higher elevation */
  --bg-inset:#08090b; --bg-base:#0c0e11; --bg-subtle:#111418;
  --bg-surface:#16191d; --bg-elevated:#1d2127; --bg-overlay:rgba(6,7,9,.66);
  /* borders */
  --border-subtle:#1e2228; --border-default:#282d34; --border-strong:#363c44;
  /* text (not pure white — avoids halation) */
  --text-primary:#e7eaed; --text-secondary:#9aa3ad; --text-muted:#6b747d; --text-faint:#4a525a;
  /* accent (calm azure): interactive / focus only */
  --accent:#5b93f5; --accent-hover:#6fa0f7; --accent-active:#4b82e8;
  --accent-text:#8fb6f9; --accent-bg:rgba(91,147,245,.14); --accent-border:rgba(91,147,245,.34);
  --focus-ring:rgba(91,147,245,.55);
  /* status: mid-saturation, legible on dark, non-glowing */
  --ok:#35b979;     --ok-text:#5fd39b;     --ok-bg:rgba(53,185,121,.14);
  --warn:#d99e2b;   --warn-text:#e8b84b;   --warn-bg:rgba(217,158,43,.14);
  --danger:#e0575f; --danger-text:#f2868c; --danger-bg:rgba(224,87,95,.14);
  --info:#48a7cf;   --info-text:#74c4e4;   --info-bg:rgba(72,167,207,.14);
  /* chart */
  --chart-1:#5b93f5; --chart-2:#35b979; --chart-3:#d99e2b;
  --chart-4:#b98bf5; --chart-5:#48a7cf; --chart-6:#e0575f;
  --chart-grid:#1e2228; --chart-axis:#6b747d;
  /* elevation */
  --shadow-sm:0 1px 2px rgba(0,0,0,.40);
  --shadow-md:0 4px 12px rgba(0,0,0,.45),0 1px 2px rgba(0,0,0,.30);
  --shadow-lg:0 12px 32px rgba(0,0,0,.55),0 2px 6px rgba(0,0,0,.40);
  --rim:inset 0 1px 0 rgba(255,255,255,.04);
}
```

### Color — light (override values)
```css
--bg-inset:#eceef1; --bg-base:#f6f7f9; --bg-subtle:#eef0f3; --bg-surface:#fff; --bg-elevated:#fff;
--border-subtle:#edeff2; --border-default:#e0e3e8; --border-strong:#cbd0d8;
--text-primary:#1a1d21; --text-secondary:#565d66; --text-muted:#79818b; --text-faint:#a8afb8;
--accent:#2f6fe0; --accent-hover:#2a63c9; --accent-active:#2456b0; --accent-text:#2560c9;
--accent-bg:rgba(47,111,224,.10); --accent-border:rgba(47,111,224,.28); --focus-ring:rgba(47,111,224,.45);
--ok:#1f9d5f; --ok-text:#17794a; --ok-bg:rgba(31,157,95,.12);
--warn:#b7791f; --warn-text:#8a5a12; --warn-bg:rgba(183,121,31,.12);
--danger:#d13b43; --danger-text:#b02a32; --danger-bg:rgba(209,59,67,.10);
--info:#2b83a6; --info-text:#1f6c8a; --info-bg:rgba(43,131,166,.12);
--chart-grid:#edeff2; --chart-axis:#79818b;
--shadow-sm:0 1px 2px rgba(16,24,40,.06);
--shadow-md:0 4px 12px rgba(16,24,40,.08),0 1px 3px rgba(16,24,40,.05);
--shadow-lg:0 16px 40px rgba(16,24,40,.12),0 4px 8px rgba(16,24,40,.06);
```

### Type / spacing / radius / motion
```css
--font-ui:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
--font-mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
/* scale (base 14, ratio ~1.2), weights 400/500/600 only */
--t-display:30/36/600; --t-h1:24/32/600; --t-h2:20/28/600; --t-h3:16/24/600;
--t-body:14/20/400; --t-label:13/18/500; --t-caption:12/16/500; --t-overline:11/16/600;
--t-metric-xl:32/36/600; --t-metric:20/24/500; --t-mono-sm:12/18/400;
/* spacing (4px base) */
--s1:2; --s2:4; --s3:8; --s4:12; --s5:16; --s6:20; --s7:24; --s8:32; --s9:40; --s10:48;
/* radius */
--r-xs:4px; --r-sm:6px; --r-md:8px; --r-lg:12px; --r-xl:16px; --r-full:9999px;
/* motion */
--ease:cubic-bezier(.4,0,.2,1); --ease-out:cubic-bezier(.22,1,.36,1);
--dur-fast:120ms; --dur:180ms; --dur-slow:240ms;
```
**Mandatory:** `font-variant-numeric: tabular-nums` on every live/columnar
number. Weights capped at 600 (no bold). Respect `prefers-reduced-motion`.

---

## 3. Information architecture

**One authoritative vertical scroll; a container-detail *drawer* for drill-in;
no top-level tabs** (health must never be a click away). Top ~120px answers
"is anything on fire?" on load.

```
TOP BAR (sticky)   identity · GLOBAL HEALTH VERDICT · updated Ns ago · ⌘K · theme · sign out
HERO LINE          one sentence ("Everything's nominal." / "redis at 92% memory") + range selector
HOST KPI ROW       6 stat cards: CPU · Memory · Swap · Disk · Load · Uptime  (big number + meter + sparkline)
HOST CHART GRID    4 time-series: CPU% · Mem/Swap · Disk-IO+Net · Load (synchronized crosshair)
CONTAINERS         worst-first table: state·name·image · health · CPU/mem sparklines · restarts · uptime
ALERTS             active alerts worst-first, or the earned "✓ All clear" state
FOOTER             os/kernel/cpu/ram · agent version · poll interval
```
Drawer (per container): Overview (per-container charts + stat strip + restart
ticks) · Logs (live tail) · Meta (image/ports/mounts/env-count, copy-on-click).
Deep-linkable: `#/c/<name>/logs?range=6h`.

---

## 4. Charts & live data (decisions)

- **Big time-series → uPlot**, vendored (~40KB, ~12KB gz) and embedded (no CDN);
  IIFE global, columnar data maps 1:1 to `/api/series` + typed-array rings.
- **Sparklines, gauge, heartbeat strip → hand-rolled** canvas/SVG (~150 lines).
  Do NOT spin up 20 uPlots for in-table sparklines.
- **Live loop:** poll `/api/status` on a self-scheduling `setTimeout` chain
  (2s, `AbortController` timeout, exp-backoff on failure) → write ring buffers →
  a single `requestAnimationFrame` repaints only dirty charts. `setData(data,
  false)` keeps the y-scale (no breathing axis). Hysteresis range. Trust
  `snap.ts` (server clock). Cap DPR at 2. `IntersectionObserver` pauses
  off-screen charts; abort polls on `visibilitychange`.
- **Log viewer:** `EventSource` (SSE) → batch into DOM once/frame → hard cap 500
  lines (model + DOM) → auto-scroll that **pauses when the user scrolls up**
  ("⏸ N new ↓" pill) → level+substring filter → color only the level token →
  **escapeHtml** (logs are hostile input).
- **Theming:** charts read tokens via `getComputedStyle` at option-build; on a
  `themechange` event, patch strokes/grids, invalidate gradient cache, redraw.
  SVG/DOM (gauge, heartbeat, log colors) recolor via `var(--…)` for free.
- **No-lie rule:** draw the mean line + a min/max band (from `/api/series`);
  EMA only for the hero number, never chart geometry.

---

## 5. Signature "premium" details (cheap, high-impact)

Surface ladder + hairlines (not shadows) · tabular-nums everywhere · one accent
used almost nowhere · gradient area fills under lines · consistent 4/6/8/12
radius · micro-transitions on *state* not on load · synchronized crosshair
across host charts · "⏸ N new lines" log pill · uptime restart-tick strip ·
favicon + tab-title as a live status channel (`▲ host — 1 down`) · earned
"✓ All clear · healthy for 6d" empty state · copy-anything mono values ·
deep-linkable drawer/range/filter · reduced-motion honesty · **never render
green while stale** (hold last value, dim it, show "reconnecting…").

## Anti-patterns (avoid)
Enterprise fleet shell / left-rail nav · a dashboard *builder* · a wall of
radial gauges · rainbow series · heavy chart chrome (vertical grid, legends for
one series) · full DOM rebuild on tick · auto-scrolling logs while reading ·
over-smoothing away real spikes · any external font/CDN/beacon · alarming on a
single transient blip (debounce).

---

## 6. Build order (phased)

**Backend prerequisites** (needed for the headline features):
- **B1 — container usage:** per-container CPU%/mem via the Docker stats stream
  (extend the M0 docker collector).
- **B2 — time-series store:** SQLite tiered rollups + `GET /api/series` (SPEC §3).
- **B3 — logs:** `GET /api/logs/:container` SSE from the Docker socket (SPEC §7).

**Frontend phases** (each deployable):
1. **Design system + shell** — `tokens.css`, sticky top bar (identity + global
   health verdict + updated-ticker + theme toggle + sign out), the rAF live
   loop, stale handling. *(works on current `/api/status`)*
2. **Host KPI row** — 6 stat cards with meters + client-side sparklines (short
   in-browser ring buffer until B2). *(current data)*
3. **Container table** — worst-first, status pills, health, restarts, uptime;
   CPU/mem columns show "not collected" until **B1**. *(current data + B1)*
4. **Host charts** — uPlot grid + range selector + synchronized crosshair.
   *(needs B2)*
5. **Container drawer** — Overview + Meta, deep-linked. *(B1)*
6. **Live logs** — the flagship. *(needs B3)*
7. **Alerts panel** + earned all-clear. *(needs M1 alerting)*
8. **Polish** — command palette, keyboard map (⌘K, /, j/k, esc, 1–5, t),
   density toggle, favicon/title status, copy-anything, theme contrast pass.

Ship 1–3 first (immediate premium feel on today's data); 4–6 are the
"overengineered" core; 7–8 the finish. Backend B1→B2→B3 unlock 3/4/6.

---

_Panel sources: Netdata · Grafana · Datadog · Vercel · Linear · Fly · Sentry ·
Uptime Kuma · Beszel · Refactoring UI · Radix Colors · Josh Comeau (dark mode) ·
Vercel Geist · uPlot._
