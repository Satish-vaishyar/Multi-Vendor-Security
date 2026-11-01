/* Role helpers - mirror of backend/app/core/rbac.py (the server is the authority;
   this only hides controls the API would reject with 403). */
export const ROLES = ["VIEWER", "AUDITOR", "APPROVER", "ADMIN"] as const;
export type Role = (typeof ROLES)[number];

export function hasRole(role: string | undefined | null, min: Role): boolean {
  const have = ROLES.indexOf(String(role ?? "").toUpperCase() as Role);
  return have >= 0 && have >= ROLES.indexOf(min);
}
