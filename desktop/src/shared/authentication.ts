export interface AuthenticationRequest {
  runDir: string; url: string; mode: 'basic' | 'form';
  usernameSource: 'single' | 'wordlist'; username: string; usernameWordlist: string; passwordWordlist: string;
  usernameField: string; passwordField: string; extraBody: string;
  successMode: 'auto' | 'body' | 'location'; successValue: string; failureValue: string; lockoutValue: string;
  maxAttempts: number; duration: number; timeout: number; delay: number;
}
export type AuthenticationStatus = 'running' | 'accepted' | 'candidate' | 'no_candidate' | 'not_accepted' | 'attempt_limit' | 'blocked' | 'inconclusive' | 'cancelled' | 'timed_out' | 'failed';
export interface AuthenticationAttempt { username: string; password: string; statusCode: number; outcome: string; detail: string; }
export interface AuthenticationJob extends AuthenticationRequest {
  target: string; jobId: string; jobDir: string; reportPath: string; startedAt: string; finishedAt?: string;
  status: AuthenticationStatus; attempts: AuthenticationAttempt[]; message?: string; baselineRequests: number; plannedAttempts: number;
  attemptCount?: number; diagnostic?: string;
  acceptedAttempts?: AuthenticationAttempt[]; rejectedAttempts?: AuthenticationAttempt[]; otherAttempts?: AuthenticationAttempt[];
  candidateAttempts?: AuthenticationAttempt[]; comparisonRequests?: number;
  rejectedCount?: number; rejectedPage?: number; rejectedPages?: number;
}
export interface AuthenticationSnapshot { active: AuthenticationJob | null; jobs: AuthenticationJob[]; log: string; }

export function validateAuthenticationRequest(input: AuthenticationRequest, target: string): void {
  const url = new URL(input.url), origin = new URL(target.includes('://') ? target : `http://${target}`);
  const port = (value: URL): string => value.port || (value.protocol === 'https:' ? '443' : '80');
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || /[\r\n\0]/.test(input.url)) throw new Error('Use an HTTP(S) URL without embedded credentials or fragments.');
  if (url.hostname.toLowerCase() !== origin.hostname.toLowerCase() || port(url) !== port(origin)) throw new Error('The validation URL must belong to the selected scan target (same host and port).');
  if (!['basic', 'form'].includes(input.mode) || !['single', 'wordlist'].includes(input.usernameSource)) throw new Error('Invalid authentication method or username source.');
  for (const key of ['username', 'usernameWordlist', 'passwordWordlist', 'usernameField', 'passwordField', 'extraBody', 'successValue', 'failureValue', 'lockoutValue'] as const) {
    if (typeof input[key] !== 'string' || input[key].length > (key === 'extraBody' ? 16384 : 4096) || input[key].includes('\0')) throw new Error('Invalid authentication input.');
  }
  if (!input.passwordWordlist.trim() || !(input.usernameSource === 'single' ? input.username.length : input.usernameWordlist.trim().length)) throw new Error('Choose a username and password wordlist.');
  if (input.mode === 'basic' && input.usernameSource === 'single' && /[:\r\n]/.test(input.username)) throw new Error('HTTP Basic usernames cannot contain colon or newline characters.');
  if (input.mode === 'form') {
    for (const key of ['usernameField', 'passwordField'] as const) if (!/^[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,127}$/.test(input[key])) throw new Error('Enter the exact username and password form field names.');
    if (input.usernameField === input.passwordField) throw new Error('Username and password form fields must be different.');
    const extra = new URLSearchParams(input.extraBody);
    if (extra.has(input.usernameField) || extra.has(input.passwordField)) throw new Error('Additional form values must not overwrite credential fields.');
    if (!['auto', 'body', 'location'].includes(input.successMode)) throw new Error('Choose automatic comparison or an explicit success criterion.');
    if (input.successMode !== 'auto' && (input.successValue.trim().length < 3 || input.failureValue.trim().length < 3)) throw new Error('Set explicit success and failure indicators for the login form.');
    if (input.successMode === 'auto' && input.failureValue && input.failureValue.trim().length < 3) throw new Error('Optional failed login text must contain at least three characters.');
    if (input.successMode === 'body' && input.successValue === input.failureValue) throw new Error('Success and failure indicators must be different.');
    if (input.successMode === 'location') {
      const destination = new URL(input.successValue, url);
      if (destination.origin !== url.origin || destination.username || destination.password || destination.hash) throw new Error('The success redirect must be on the same origin.');
    }
  }
  for (const [key, min, max] of [['maxAttempts', 1, 1000], ['duration', 10, 1800], ['timeout', 2, 30]] as const) if (!Number.isInteger(input[key]) || input[key] < min || input[key] > max) throw new Error(`${key} must be an integer between ${min} and ${max}.`);
  if (!Number.isFinite(input.delay) || input.delay < 0 || input.delay > 10) throw new Error('Request delay must be between 0 and 10 seconds.');
}
