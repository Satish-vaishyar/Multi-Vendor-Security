import { Page } from '@playwright/test';

export interface A11yIssue { rule: string; detail: string }

/**
 * Lightweight accessibility smoke (the project does not depend on @axe-core/playwright, and it must not be added
 * for this check). Covers the mechanical WCAG failures that account for most real-world problems:
 *  - every visible form control has an accessible name (label, aria-label, aria-labelledby)
 *  - every visible button / link / [role=button|tab|option] has an accessible name
 *  - every <img> has alt; every svg with role=img has a name
 *  - exactly one <h1>, heading levels never skip downwards (h1 -> h3)
 *  - <html lang>, non-empty <title>, a <main> landmark, unique ids
 *  - dialogs have a name and aria-modal
 * Colour contrast is verified separately (docs/UI_GUIDE.md, computed from the design tokens).
 */
export async function a11yIssues(page: Page): Promise<A11yIssue[]> {
  return page.evaluate(() => {
    const issues: { rule: string; detail: string }[] = [];
    const vis = (el: Element) => {
      const r = (el as HTMLElement).getBoundingClientRect();
      const cs = getComputedStyle(el as HTMLElement);
      return cs.visibility !== 'hidden' && cs.display !== 'none' && (r.width > 0 || r.height > 0 || cs.position === 'fixed');
    };
    const txt = (el: Element) => (el.textContent ?? '').replace(/\s+/g, ' ').trim();
    const labelledBy = (el: Element) =>
      (el.getAttribute('aria-labelledby') ?? '').split(/\s+/).filter(Boolean).map((id) => txt(document.getElementById(id) ?? document.body)).join(' ').trim();
    const name = (el: Element) => {
      const aria = (el.getAttribute('aria-label') ?? '').trim();
      if (aria) return aria;
      const lb = labelledBy(el);
      if (lb) return lb;
      const id = el.getAttribute('id');
      if (id) {
        const l = document.querySelector(`label[for="${CSS.escape(id)}"]`);
        if (l && txt(l)) return txt(l);
      }
      const wrap = el.closest('label');
      if (wrap && txt(wrap)) return txt(wrap);
      return '';
    };
    const desc = (el: Element) => `<${el.tagName.toLowerCase()}${el.id ? '#' + el.id : ''}${(el as HTMLElement).className && typeof (el as HTMLElement).className === 'string' ? '.' + (el as HTMLElement).className.split(/\s+/).slice(0, 2).join('.') : ''}> ${txt(el).slice(0, 40)}`;

    document.querySelectorAll('input, select, textarea').forEach((el) => {
      const t = (el as HTMLInputElement).type;
      if (['hidden', 'submit', 'button', 'reset', 'image'].includes(t) || !vis(el) && !el.classList.contains('sr-only')) return;
      if (!name(el) && !(el.getAttribute('title') ?? '').trim()) issues.push({ rule: 'form-control-name', detail: desc(el) + ` placeholder="${el.getAttribute('placeholder') ?? ''}"` });
    });
    document.querySelectorAll('button, a[href], [role=button], [role=tab], [role=option], [role=menuitem]').forEach((el) => {
      if (!vis(el)) return;
      const n = txt(el) || name(el) || (el.getAttribute('title') ?? '').trim() || (el.querySelector('img[alt]')?.getAttribute('alt') ?? '');
      if (!n) issues.push({ rule: 'interactive-name', detail: desc(el) });
    });
    document.querySelectorAll('img').forEach((el) => {
      if (!el.hasAttribute('alt')) issues.push({ rule: 'img-alt', detail: desc(el) });
    });
    document.querySelectorAll('[role=img]').forEach((el) => {
      if (!name(el)) issues.push({ rule: 'role-img-name', detail: desc(el) });
    });
    const h = [...document.querySelectorAll('h1,h2,h3,h4,h5,h6')].filter(vis);
    const h1 = h.filter((x) => x.tagName === 'H1').length;
    if (h1 !== 1) issues.push({ rule: 'single-h1', detail: `found ${h1} h1 elements` });
    let prev = 0;
    for (const el of h) {
      const lvl = Number(el.tagName[1]);
      if (prev && lvl > prev + 1) issues.push({ rule: 'heading-order', detail: `${el.tagName} "${txt(el).slice(0, 40)}" follows h${prev}` });
      prev = lvl;
    }
    if (!document.documentElement.lang) issues.push({ rule: 'html-lang', detail: 'missing lang' });
    if (!document.title.trim()) issues.push({ rule: 'document-title', detail: 'empty title' });
    if (!document.querySelector('main')) issues.push({ rule: 'main-landmark', detail: 'no <main>' });
    const seen = new Set<string>();
    document.querySelectorAll('[id]').forEach((el) => {
      if (seen.has(el.id)) issues.push({ rule: 'duplicate-id', detail: el.id });
      seen.add(el.id);
    });
    document.querySelectorAll('[role=dialog]').forEach((el) => {
      if (!name(el)) issues.push({ rule: 'dialog-name', detail: desc(el) });
      if (el.getAttribute('aria-modal') !== 'true') issues.push({ rule: 'dialog-modal', detail: desc(el) });
    });
    return issues;
  });
}
