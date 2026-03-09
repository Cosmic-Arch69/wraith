// Password Mutation Engine -- generates password candidates from known context
// Part of Wraith v2.1 Feature F5

export interface MutationContext {
  domain: string;       // e.g. 'YASHnet.local'
  usernames: string[];  // known usernames
  hostnames: string[];  // known hostnames
}

const CURRENT_YEARS = ['2024', '2025', '2026'];
const COMMON_SUFFIXES = ['!', '@', '#', '123', '1234', '2024', '2025', '2026', '!@#'];
const KEYBOARD_WALKS = ['qwerty', 'qwerty123', '1qaz2wsx', '1qaz!QAZ', 'zxcvbnm', 'Password1'];

function leetSpeak(s: string): string {
  return s
    .replace(/a/gi, '@')
    .replace(/e/gi, '3')
    .replace(/i/gi, '!')
    .replace(/o/gi, '0')
    .replace(/s/gi, '$');
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

function domainShort(domain: string): string {
  // 'YASHnet.local' -> 'YASHnet'
  return domain.split('.')[0] ?? domain;
}

export function generateMutations(
  passwords: string[],
  context: MutationContext,
): string[] {
  const candidates = new Set<string>();
  const domainBase = domainShort(context.domain);
  const domainLower = domainBase.toLowerCase();

  // Rule 8: Keyboard walks (added first so they're lower priority -- domain-themed get priority)
  for (const walk of KEYBOARD_WALKS) {
    candidates.add(walk);
  }

  // Rule 7: Hostname combos
  for (const host of context.hostnames) {
    for (const suffix of COMMON_SUFFIXES) {
      candidates.add(host + suffix);
    }
    candidates.add(host + '!');
    candidates.add(capitalize(host) + '1');
  }

  // Rule 6: Username-based
  for (const user of context.usernames) {
    for (const year of CURRENT_YEARS) {
      candidates.add(user + year + '!');
    }
    candidates.add(user + '@' + domainBase);
    candidates.add(user + domainBase);
    candidates.add(capitalize(user) + '123');
  }

  // Base password mutations (rules 2-5)
  for (const pw of passwords) {
    // Rule 4: Case variants
    candidates.add(pw.toLowerCase());
    candidates.add(pw.toUpperCase());
    candidates.add(capitalize(pw));

    // Rule 3: Leet speak
    candidates.add(leetSpeak(pw));
    candidates.add(leetSpeak(pw.toLowerCase()));

    // Rule 5: Common suffixes
    for (const suffix of COMMON_SUFFIXES) {
      candidates.add(pw + suffix);
      candidates.add(capitalize(pw) + suffix);
    }

    // Rule 2: Year append
    for (const year of CURRENT_YEARS) {
      candidates.add(pw + year);
      candidates.add(pw + year + '!');
      candidates.add(capitalize(pw) + year);
      candidates.add(capitalize(pw) + year + '!');
    }

    // Include base password itself
    candidates.add(pw);
  }

  // Rule 1: Domain prefix/suffix -- added last so they end up at front after priority sort
  const domainCandidates: string[] = [];
  for (const year of CURRENT_YEARS) {
    domainCandidates.push(domainBase + year + '!');
    domainCandidates.push(domainBase + '@' + year);
    domainCandidates.push(domainLower + year);
    domainCandidates.push(capitalize(domainLower) + year + '!');
  }
  domainCandidates.push(domainBase + '!');
  domainCandidates.push(domainBase + '123');
  domainCandidates.push(domainBase + '@2026');
  domainCandidates.push(domainLower + '2024!');
  domainCandidates.push(leetSpeak(domainLower) + '2024');

  // Build final list: domain-themed first, then rest
  const domainSet = new Set(domainCandidates);
  const rest = Array.from(candidates).filter(c => !domainSet.has(c));
  const all = [...domainCandidates, ...rest];

  // Deduplicate preserving order and cap at 2000
  const seen = new Set<string>();
  const deduped: string[] = [];
  for (const c of all) {
    if (!seen.has(c)) {
      seen.add(c);
      deduped.push(c);
      if (deduped.length >= 2000) break;
    }
  }

  return deduped;
}
