import { useEffect, useState } from "react";

/* Milestones the server cannot know about (e.g. "opened the findings list"). Kept in this browser only. */
const KEY = "qirova_progress";
const EVT = "qirova-progress";

export type Milestone = "findings" | "fixes" | "report";

function read(): Record<string, boolean> {
  try { return JSON.parse(localStorage.getItem(KEY) ?? "{}") as Record<string, boolean>; } catch { return {}; }
}

export function markMilestone(m: Milestone) {
  try {
    const cur = read();
    if (cur[m]) return;
    localStorage.setItem(KEY, JSON.stringify({ ...cur, [m]: true }));
    window.dispatchEvent(new Event(EVT));
  } catch { /* storage blocked - checklist simply stays unticked */ }
}

export function useMilestones(): Record<string, boolean> {
  const [v, setV] = useState(read);
  useEffect(() => {
    const on = () => setV(read());
    window.addEventListener(EVT, on);
    window.addEventListener("storage", on);
    return () => { window.removeEventListener(EVT, on); window.removeEventListener("storage", on); };
  }, []);
  return v;
}
