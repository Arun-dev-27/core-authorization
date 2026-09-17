/**
 * Pure decisions behind onboarding an ITS user into the Core Admin Control Panel.
 *
 * Kept out of the CLI in `scripts/onboard-its-users.ts` so the rules can be tested without a
 * database, and so a future HTTP endpoint can reuse exactly the same logic.
 */

export interface Assignment {
  itsId: string;
  roleCodes: string[];
}

/** miqaat_core.users.its_id is varchar(8) with a CHECK for exactly eight digits. */
export const ITS_ID_PATTERN = /^[0-9]{8}$/;

/**
 * Parses `--assign <itsId>:<roleCode>[,<roleCode>...]` values.
 *
 * Repeating an ITS ID merges its roles rather than overwriting, so `--assign 1:a --assign 1:b` is
 * the same request as `--assign 1:a,b`; duplicate role codes collapse.
 */
export function parseAssignments(values: readonly string[]): Assignment[] {
  const byIts = new Map<string, string[]>();
  for (const raw of values) {
    const separator = raw.indexOf(':');
    if (separator === -1) throw new Error(`--assign expects <itsId>:<roleCode>[,<roleCode>...], got "${raw}"`);
    const itsId = raw.slice(0, separator).trim();
    const roleList = raw.slice(separator + 1);
    if (!ITS_ID_PATTERN.test(itsId)) throw new Error(`"${itsId}" is not an 8-digit ITS ID`);
    const roles = roleList.split(',').map((r) => r.trim()).filter(Boolean);
    if (roles.length === 0) throw new Error(`no role codes given for ${itsId}`);
    byIts.set(itsId, [...new Set([...(byIts.get(itsId) ?? []), ...roles])]);
  }
  return [...byIts].map(([itsId, roleCodes]) => ({ itsId, roleCodes }));
}

/**
 * Chooses the email an onboarded user is created with.
 *
 * `miqaat_core.users.email` is NOT NULL and UNIQUE, while the upstream profile routinely omits an
 * address or repeats one across many people. A candidate is therefore used only when it exists and
 * is still free; otherwise the address is derived from the ITS ID under `.invalid`, the TLD RFC 2606
 * reserves precisely so it can never resolve to a real mailbox.
 */
export function chooseEmail(
  itsId: string,
  candidate: string | null | undefined,
  isTaken: boolean,
): { email: string; synthesized: boolean } {
  const cleaned = candidate?.trim().toLowerCase() || null;
  if (cleaned && !isTaken) return { email: cleaned, synthesized: false };
  return { email: `its-${itsId}@placeholder.invalid`, synthesized: true };
}

/** Display name for a user whose upstream profile has no usable name. */
export function chooseName(itsId: string, candidate: string | null | undefined): string {
  return candidate?.trim() || `ITS ${itsId}`;
}
