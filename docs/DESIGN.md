# ShieldIQ design (round 5: industrial blueprint, minimal)

## The idea, in one line

**Find the holes in your cloud — before attackers do — and fix them in one click.** Every screen says that one thing,
in plain words, with as little on screen as possible.

The visual direction is **inspired by a Dribbble reference** (an "AI financial intelligence" landing page by a design
studio) that the project owner chose: an industrial / technical-editorial look. ShieldIQ borrows its *language*
(palette, type, hairlines, isometric 3D, the numbered scroll story), not its text, brand or content.

## Who it is for

| Person | Situation | What the design does for them |
|---|---|---|
| A non-technical visitor or recruiter | 5 seconds on the landing page | A three-line headline, one sentence, one button, and a scroll story that acts out Connect → Scan → Prioritise → Fix → Prove, one step at a time. |
| A security engineer | Triaging | The dashboard leads with one message ("38 critical issues. Fix these first."), then the riskiest attack path drawn. Orange only where it matters. |
| A platform engineer | Fixing one finding | The fix as code, one orange button, and proof (re-scan) that it worked. |

## Principles

1. **One idea per section.** Five landing sections: hero, scroll story, three features, one stat row, guides + CTA,
   then the footer. The FAQ lives on the guides page.
2. **Empty space is the layout.** ~200px section padding on desktop, 48–64px gutters, body text at 1.7 line height
   and ≤ 60ch. Only one or two hairlines per section, used to frame, never to fence every cell.
3. **Orange means "critical" or "fix".** Everything else is charcoal on warm grey. If orange appears, it is either a
   problem to look at or the button that solves it.
4. **Real data only.** Every number on the landing page (checks, platforms, frameworks, the path's issues, the score
   before/after) is read from the code and the demo workspace at request time.
5. **Honest.** A student portfolio project; provider marks appear only as "works with"; no customers, logos or quotes.

## Identity

- **Mark:** one isometric block of your cloud estate — light and grey sides with its top face in signal orange
  ("this block has a hole"), on a charcoal tile so it reads at 16px (`templates/brand.html`, `static/img/logo.svg`).
- **Wordmark:** `SHIELD` + orange `IQ`, Archivo at its widest (wdth 125), uppercase.

## Palette (`static/css/siq.css`)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--paper` | `#e4e4e1` | `#141413` | canvas |
| `--surface` | `#f6f6f4` | `#1d1d1c` | cells / cards (no outline) |
| `--ink` | `#151515` | `#ededea` | text, primary buttons (black pill) |
| `--ink-2/3` | `#4a4a47` / `#82827d` | `#b4b4ae` / `#7d7d78` | secondary text, labels |
| `--hair` | 14% ink | 12% bone | the few blueprint hairlines |
| `--or` | `#ff5a1f` | `#ff6a33` | critical severity, fix actions, the attack path |
| `--char` | `#151515` | — | charcoal sections (features, footer) |

Severity: critical = solid orange tag; high = ink outline; medium = grey; low = hollow. Rank survives without colour.

## Type

- **Display:** Archivo (variable, vendored OFL) at `font-stretch: 125%` / `wdth 125`, 700, uppercase, tight tracking.
- **Labels and values:** Geist Mono, uppercase, letter-spaced (`01/05`, `FIX HERE`, resource IDs).
- **Reading:** Inter, 15–19px, 1.7 line height.

## 3D objects (all SVG, generated geometry, themable, no images, no WebGL)

| Object | Where | How |
|---|---|---|
| **ShieldIQ module** (`module()` in `templates/_iso.html`) | landing hero, sign-in/register | Isometric appliance in 4 layers: chassis with vents and an orange toggle and trim, orange core board with an LED grid and a chip, glass cover, cap. Faces use light→shade gradients; strokes are 0.8px non-scaling hairlines. |
| **Cloud estate** (`estate()`) | landing scroll story, dashboard, attack-paths page | The real riskiest attack path's node types as blocks on a gridded platform: internet (wire cube) → firewall rule (wall) → server (3-plate stack) → access role (cube) → customer data (two-drum cylinder), plus neutral estate blocks. Every face is drawn three times (neutral fill, orange overlay, hairline stroke), so state changes are opacity crossfades. Labels and issue counts come from the live path. |
| **Exploded stack** (`stack()`) | landing features section | The four layers of a scan (your config, 64 checks, attack graph, fix + proof) as plates that separate on scroll. |

The geometry was generated once with a small isometric projection (x = (gx − gy)·cos30°, y = (gx + gy)·sin30° − z) and
committed as markup, so pages render without JavaScript and screenshots are deterministic.

## Motion (every animation has one job)

All motion is time-based (rAF timestamps, CSS transitions or the Web Animations API), so it plays at the same speed
on 60, 120 or 144 Hz screens. Only `transform` and `opacity` animate, plus one-shot SVG stroke draws. Under
`prefers-reduced-motion` every element shows its end state.

| Animation | Where | Purpose |
|---|---|---|
| Headline lines rise out of a mask, then the sentence and button fade up | hero | Reading order: what, then why, then act. |
| Module layers assemble, breathe slightly apart, and explode as you scroll away | hero | Shows the product is layered (config → checks → graph → fix) without words. |
| Pinned scroll story, one step at a time; five progress segments; clickable | `/#how` | One idea at a time for non-technical visitors. |
| Blocks drop in left→right | story step 1 | "Connect": your cloud appears. |
| An orange scan plane sweeps across; risky blocks turn orange as it passes; issue counts pop | step 2 | Cause → effect: the scan finds the holes. |
| The attack path draws across the blocks with packets flowing toward the data; brackets lock onto the weak point | step 3 | Direction of risk and where to act. |
| A cut mark spins in, the path turns to a grey dashed line, orange drains from the path's blocks, the issue count rolls to 0 | step 4 | The fix breaks the chain. |
| A second, ink-coloured sweep; the score rolls from before to after | step 5 | Proof by re-scan. |
| Scene tilts slightly with scroll progress (scrubbed, smoothed) | story | Depth; feels like turning a model. |
| Stack plates separate (scrubbed) | features | Explains the four layers of a scan. |
| Numbers count up once when seen | stat row, dashboard | Draws the eye to the figures that matter. |
| Nav link underline draws; button arrow turns; cells outline on hover | everywhere | Affordance. |
| Dial sweeps to the score; bars grow; odometer counts; findings strike through when fixed | app | Read the score as a position; confirm the fix. |

## App language

- **Shell:** the sidebar is a quiet column of mono rows; the active row is a solid ink bar with an orange icon. The
  topbar is translucent with no rule. The command palette, menus and modals are square with one hairline.
- **Cells:** white surfaces on the grey canvas, no outline, 32px padding; ruled lines only between table rows.
- **Page head:** a wide uppercase title, a short mono label above it, a sentence of context.
- **Dashboard:** (1) one message — the score dial beside "N critical issues. Fix these first." and one orange button;
  (2) the riskiest attack path drawn isometrically with "Fix here" and "Open the fix"; (3) three big numbers;
  (4) the fix-first list and severity bars; then compliance and alerts.
- **Buttons:** black pill = primary; orange pill = fix (auto-fix, fix critical issues, open the fix); outline = secondary.
- **Dark theme:** charcoal canvas, bone text, the same orange; the isometric blocks switch to dark faces with light
  hairlines.
- **Mobile:** single column; the scroll story is no longer pinned and steps through on its own while visible.

## Files

- `static/css/siq.css` — tokens, the isometric scene styles, the app re-skin layer (loaded after `app.css`).
- `static/css/landing.css` — public pages (landing, guides).
- `static/js/landing.js` — hero, story, stack, counters; `static/js/motion.js` — the shared time-based engine.
- `templates/_iso.html` — the module, estate and stack SVG macros.

## Constraints kept

CSP stays `script-src 'self'` (no inline scripts; data islands are `application/json`), all fonts and code are
vendored, every route, form field and flash message is unchanged, and the full test suite passes.
