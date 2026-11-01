# QIROVA UI guide

How the frontend (`frontend/`) is designed, how to extend it, and what to check before shipping a page.

## Design principles

1. **Self-explanatory first.** A first-time user should know what to do next without a manual. Every list page has an empty state with one call to action; jargon (CVE, PQC, CBOM, STIG, drift, risk acceptance) gets a `<Hint>`.
2. **One primary action per page.** One filled button (`btnPrimary`); everything else is `btnGhost` or a link.
3. **Colour means status.** Surfaces are calm neutrals. Colour appears only for severity and status, always with an icon and text next to it (never colour alone).
4. **Flat and quiet.** Hairline borders, no shadows on cards, one spacing scale (Tailwind 1/2/3/4/5/6), one type scale (below).
5. **Fast.** Every page is a lazy route, heavy libraries (recharts) load on demand, lists show skeletons, queries are cached for 60 s.
6. **Accessible by default.** Visible focus ring, keyboard reachable navigation, `prefers-reduced-motion` respected, AA contrast in both themes.

## Information architecture

Defined once in `src/components/layout/nav.ts` (`NAV_GROUPS`). The sidebar, the mobile drawer, the Ctrl/Cmd+K palette and the breadcrumbs all read from it.

| Section | Pages |
| --- | --- |
| Start | Get started, Dashboard |
| Audit | Devices, Upload & audit, Audit results |
| Findings | Findings, Vulnerabilities, Post-quantum, Security analytics, Compliance |
| Fix & report | Remediation, Reports, Risk acceptance |
| Automate | Recurring audits, Background jobs, Integrations (admin) |
| Admin | AI training, Administration (admin), Settings |

Items can set `min` (minimum role, mirrors `src/utils/roles.ts`): below it the item is hidden from the sidebar and the palette. The server remains the authority. Groups collapse (remembered in `localStorage`, the active group never collapses). Below 1024 px the sidebar becomes a drawer.

Pages that are not in the menu (details, advanced upload) get a breadcrumb via the `EXTRA` table in the same file.

## Tokens

Defined in `src/index.css` as CSS variables, with a light set on `:root` and a dark set on `:root[data-theme="dark"]`; exposed to Tailwind through `@theme inline`.

| Tailwind | Variable | Use |
| --- | --- | --- |
| `bg-canvas` | `--background` | page background |
| `bg-surface` / `bg-surface2` | `--surface`, `--surface-secondary` | cards / inset areas |
| `text-ink` / `ink2` / `ink3` | `--text-primary/secondary/muted` | text, strongest to quietest |
| `border-line` / `linestrong` | `--border`, `--border-strong` | hairlines / input borders |
| `bg-primary`, `text-onprimary`, `bg-primarylight` | `--primary`... | the one accent |
| `ok`, `warn`, `danger`, `high`, `info` (+ `bg` variants) | status colours | status/severity only |
| `pqc`, `ai` (+ `bg`) | | reserved for post-quantum and AI content |

Type scale: page title `text-xl sm:text-2xl font-semibold`, card title `text-sm font-semibold`, body `text-sm`, helper `text-xs`, table header `11px uppercase`. Radius: cards `rounded-xl`, controls `rounded-lg`.

### Contrast

All text/background pairs used by the tokens are verified at WCAG AA (4.5:1) in both themes by a script that parses `index.css` (text on canvas/surface/surface2, primary on its tints, on-primary on primary, every status colour on its own tint and on the surfaces). Lowest measured ratio: 4.99:1 (light, warning text on surface2), 5.15:1 (dark). When you retune a colour, re-run the check (see below).

### Theme

`public/theme-init.js` is an external synchronous script in `<head>` (CSP is `script-src 'self'`, so no inline script). It sets `data-theme` from `localStorage["qirova_theme"]` (`light`, `dark` or `system`) before first paint, so there is no flash. `stores/ui.ts` owns changes at runtime. The header has a three-way toggle.

## Components (`src/components/common.tsx`)

| Component | Notes |
| --- | --- |
| `PageHeader` | `title`, `sub` (string or JSX, may contain `<Hint>`), `actions` |
| `Card` | `title` (string or JSX), `sub`, `right`, `className` |
| `Badge` | `kind="sev"` or `"status"`; icon + text. `AiBadge`, `PqcBadge` for AI/PQC |
| `Loader` / `KpiSkeleton` / `Skeleton` | skeleton placeholders; the `label` stays available to screen readers |
| `Empty` | `label`, `hint`, `action` (put the CTA here), `icon` |
| `ErrorState` | message + Retry (keeps the text "Unable to load data." used by tests) |
| `Notice` | `kind="ok" | "error" | "info"`, `testId` |
| `Hint` / `Term` | plain-language tooltip. `<Hint term="CVE" />` reads `GLOSSARY` in `src/constants/index.ts`; or pass `text` |
| `Field`, `inputCls`, `btnPrimary`, `btnGhost` | form and button styles |

Tables are plain `<table>`. Global rules in `index.css` give them a sticky header, calm density and sideways scrolling inside the card on phones; wrap a table in `<div className="overflow-x-auto">` (or `tbl-flat` for short tables that should not scroll vertically). Grid children get `min-width: 0` globally so wide content scrolls inside its card instead of the page.

First-run helpers: `src/utils/progress.ts` stores browser-side milestones (opened findings, opened fix commands, created a report) used by the Get started checklist; the other steps come from real API data.

## How to add a page

1. Create `src/pages/MyPage.tsx` with a default export. Start with `<PageHeader title=... sub=... actions={one primary} />`.
2. Handle all four states: loading (`Loader`/skeleton), error (`ErrorState` with `onRetry`), empty (`Empty` with a CTA), data.
3. Register a lazy route in `src/App.tsx`: `const MyPage = lazy(() => import("./pages/MyPage"));` and a `<Route>` inside the `AppLayout` group.
4. Add it to `NAV_GROUPS` in `components/layout/nav.ts` (label, one-line `desc`, icon, optional `min` role). If it is a detail page, add an `EXTRA` breadcrumb entry instead.
5. Use `data-testid` for anything an e2e test must find (see existing ids: `login-*`, `upload-*`, `quick-*`, `start-audit-*`, `report-*`).
6. Charts: import recharts only in a component loaded with `React.lazy` (see `DashboardCharts.tsx`) and read colours with `chartVars()`.
7. Check the page in light and dark at 375 and 1280 px.

## Accessibility checklist

- [ ] One `<h1>` (from `PageHeader`); breadcrumb shows where you are.
- [ ] Everything reachable and operable by keyboard; focus ring visible (global `:focus-visible`).
- [ ] Icon-only buttons have `aria-label`; decorative icons `aria-hidden`.
- [ ] Status never conveyed by colour alone (use `Badge`).
- [ ] Inputs have a visible label or `aria-label`.
- [ ] Dialogs: `role="dialog"`, `aria-modal`, close on Esc, focus moves in.
- [ ] Loading regions use `role="status"`; errors use `role="alert"`.
- [ ] No horizontal page scroll at 375, 768, 1280, 1920 px.
- [ ] Text contrast at least 4.5:1 in both themes (re-run the contrast check after touching tokens).
- [ ] Animations are covered by the global `prefers-reduced-motion` rule.

## Verifying

```bash
cd frontend
npm run build      # tsc -b && vite build, no chunk-size warning
npm run lint       # oxlint
```

Contrast check: parse the two variable blocks in `src/index.css`, compute WCAG relative luminance for each text/background pair and assert >= 4.5.
