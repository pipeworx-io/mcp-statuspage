interface McpToolDefinition {
  name: string;
  description: string;
  inputSchema: {
    type: 'object';
    properties: Record<string, unknown>;
    required?: string[];
    anyOf?: Array<{ required: string[] }>;
    oneOf?: Array<{ required: string[] }>;
    allOf?: Array<{ required: string[] }>;
  };
  outputSchema?: Record<string, unknown>;
}

interface McpToolExport {
  tools: McpToolDefinition[];
  callTool: (name: string, args: Record<string, unknown>) => Promise<unknown>;
  meter?: { credits: number };
  cost?: Record<string, unknown>;
  provider?: string;
}

/**
 * SSRF guard for fetching user- or registry-supplied URLs.
 *
 * Workers that fetch URLs an attacker can influence (submission test_endpoint,
 * scraper introspect remote_url, gateway generate_llms_txt) must run the target
 * through this first. Cloudflare Workers don't route to RFC-1918 by default, but
 * the worker is still an open-fetch primitive against internal CF services,
 * cloud metadata endpoints, and tenant-private origins reachable from egress —
 * so we enforce https-only and block private / loopback / link-local / metadata
 * hosts before the fetch.
 */

// Hostnames that must never be fetched, regardless of resolution.
const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'metadata.google.internal',
]);

/** Parse a dotted-quad IPv4 string into its 4 octets, or null if not IPv4. */
function parseIpv4(host: string): [number, number, number, number] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
  if (octets.some((o) => o > 255)) return null;
  return octets as [number, number, number, number];
}

/**
 * Expand an IPv6 literal to its 8 numeric groups, or null if it isn't one.
 *
 * Needed because you cannot pattern-match IPv6 as text: `::ffff:127.0.0.1`,
 * `::ffff:7f00:1` and `0:0:0:0:0:ffff:7f00:0001` are the same address, and
 * WHATWG URL rewrites whichever you typed into the compressed hex form. The
 * guard has to compare numbers, not strings.
 */
function expandIpv6(host: string): number[] | null {
  let h = host.split('%')[0]; // drop any zone id (fe80::1%eth0)
  if (!h.includes(':')) return null;

  // A trailing dotted quad (::ffff:127.0.0.1) is legal IPv6 text. URL normally
  // normalizes it away, but accept it so callers passing a raw hostname — not
  // one that round-tripped through URL — get the same verdict.
  const lastColon = h.lastIndexOf(':');
  const tail = h.slice(lastColon + 1);
  if (tail.includes('.')) {
    const o = parseIpv4(tail);
    if (!o) return null;
    const hi = ((o[0] << 8) | o[1]).toString(16);
    const lo = ((o[2] << 8) | o[3]).toString(16);
    h = `${h.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = h.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const back = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : [];

  let groups: string[];
  if (halves.length === 2) {
    const fill = 8 - head.length - back.length;
    if (fill < 0) return null;
    groups = [...head, ...Array(fill).fill('0'), ...back];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const nums = groups.map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  return nums.some(Number.isNaN) ? null : nums;
}

/**
 * The IPv4 address embedded in an IPv6 literal, for the three prefixes that
 * carry one, or null. Each is a way to name an IPv4 destination in IPv6 syntax,
 * so each is a way to smuggle 127.0.0.1 or 169.254.169.254 past a v4-only check.
 */
function embeddedIpv4(g: number[]): [number, number, number, number] | null {
  const low32 = (): [number, number, number, number] => [g[6] >> 8, g[6] & 0xff, g[7] >> 8, g[7] & 0xff];
  const zeroTo5 = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;
  if (zeroTo5 && g[5] === 0xffff) return low32(); // ::ffff:0:0/96  IPv4-mapped
  if (zeroTo5 && g[5] === 0) return low32();      // ::/96          IPv4-compatible (deprecated)
  if (g[0] === 0x64 && g[1] === 0xff9b) return low32(); // 64:ff9b::/96 + /48  NAT64
  return null;
}

function isPrivateIpv4([a, b]: [number, number, number, number]): boolean {
  if (a === 10) return true;                         // 10.0.0.0/8
  if (a === 127) return true;                        // loopback
  if (a === 0) return true;                          // 0.0.0.0/8
  if (a === 169 && b === 254) return true;           // link-local / cloud metadata (169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true;  // 172.16.0.0/12
  if (a === 192 && b === 168) return true;           // 192.168.0.0/16
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a >= 224) return true;                         // multicast / reserved
  return false;
}

/** True if the URL is safe to fetch (https + public host). */
function isPublicHttpUrl(raw: string): boolean {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  // https only — blocks http://, file://, gopher://, ftp://, data:, etc.
  if (u.protocol !== 'https:') return false;

  let host = u.hostname.toLowerCase();
  if (!host) return false;
  // URL.hostname returns IPv6 literals bracketed (e.g. "[fc00::1]"); strip them
  // so the prefix/equality checks below see the bare address.
  const isV6 = host.startsWith('[') && host.endsWith(']');
  if (isV6) host = host.slice(1, -1);

  if (BLOCKED_HOSTNAMES.has(host)) return false;
  // Any *.localhost / *.internal / *.local
  if (host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) return false;

  // IPv6 literals: block loopback (::1), unspecified (::), unique-local (fc00::/7),
  // and link-local (fe80::/10).
  if (isV6 || host.includes(':')) {
    if (host === '::1' || host === '::') return false;
    if (host.startsWith('fc') || host.startsWith('fd')) return false; // unique-local
    if (host.startsWith('fe8') || host.startsWith('fe9') || host.startsWith('fea') || host.startsWith('feb')) return false; // link-local

    // An IPv6 literal can carry an IPv4 destination inside it (IPv4-mapped,
    // IPv4-compatible, NAT64). Decode it and apply the same v4 rules, so
    // [::ffff:169.254.169.254] is blocked exactly like 169.254.169.254.
    //
    // This previously matched on a dotted quad in the tail — which URL never
    // produces, since it serializes IPv6 in hex — so the check was dead code
    // and mapped loopback/metadata addresses passed (2026-08-01 review).
    const groups = expandIpv6(host);
    if (groups) {
      const v4 = embeddedIpv4(groups);
      if (v4 && isPrivateIpv4(v4)) return false;
    }
    return true;
  }

  const ipv4 = parseIpv4(host);
  if (ipv4) return !isPrivateIpv4(ipv4);

  return true;
}

/** Throws an Error with a stable code-ish message if the URL isn't safe to fetch. */
function assertPublicHttpUrl(raw: string): URL {
  if (!isPublicHttpUrl(raw)) {
    throw new Error(`blocked_url: refusing to fetch non-public or non-https URL`);
  }
  return new URL(raw);
}

// Path, query, fragment, userinfo, backslash, whitespace. Every one of these
// makes `https://${host}/api/...` mean something other than it reads as.
const HOSTNAME_FORBIDDEN = /[/?#@\\\s]/;

/**
 * Validate a caller-supplied HOSTNAME that a pack will interpolate into a URL
 * (`https://${host}/api/...`). Returns the normalized `hostname[:port]`.
 *
 * Use this instead of a hand-rolled strip-and-hope (fleet #214). Pinning the
 * scheme to https:// looks like protection and is not — the host segment is
 * still attacker-controlled, and two shapes walk straight past a protocol pin:
 *
 *   QUERY TRUNCATION  host = "evil.example/collect?x="
 *     `https://evil.example/collect?x=/api/v1/timelines/tag/x` — the API path
 *     the pack appended is now part of the QUERY STRING of an attacker's URL.
 *     The pack believes it called a Mastodon endpoint. It called whatever it
 *     was pointed at, and hands the body back to the caller.
 *
 *   USERINFO CONFUSION  host = "mastodon.social@evil.example"
 *     Everything before `@` is credentials, so this fetches evil.example while
 *     reading as legitimate in a log line or a code review.
 *
 * Stripping a leading `https://` and trailing slashes — the common shape in
 * these packs — defeats neither, and a `.replace(/\/.*$/, '')` that removes a
 * path still leaves `?`, `#` and `@` untouched (verified live against three
 * packs on 2026-08-10 before this landed).
 *
 * Rejects rather than sanitizes. A host with a path in it is not a typo we
 * should guess at, and silently truncating to `evil.example` would still fetch
 * a host the caller never legitimately meant.
 *
 * @param raw   the caller-supplied value; a leading scheme and trailing
 *              slashes are tolerated because callers habitually paste URLs.
 * @param label argument name, so the error tells the agent what to fix.
 */
function assertPublicHostname(raw: unknown, label = 'host'): string {
  const input = typeof raw === 'string' ? raw.trim() : '';
  if (!input) throw new Error(`blocked_host: ${label} is empty`);

  const stripped = input.replace(/^https?:\/\//i, '').replace(/\/+$/, '');
  if (!stripped || HOSTNAME_FORBIDDEN.test(stripped)) {
    throw new Error(
      `blocked_host: ${label} "${input}" must be a bare hostname — no path, query string, fragment, "@" or whitespace.`,
    );
  }

  let u: URL;
  try {
    u = new URL(`https://${stripped}/`);
  } catch {
    throw new Error(`blocked_host: ${label} "${input}" is not a valid hostname.`);
  }

  // Reuse the vetted private/loopback/link-local/IPv6-mapped logic rather than
  // re-deriving it per pack — the packs' inlined copies each missed something
  // different (CGNAT 100.64/10 in one, IPv4-mapped IPv6 in another).
  //
  // Runs BEFORE the parse-equality check below so the caller gets the
  // informative reason. [::ffff:169.254.169.254] canonicalizes to
  // [::ffff:a9fe:a9fe], which trips equality too — "non-public host" is the
  // answer worth giving.
  if (!isPublicHttpUrl(u.toString())) {
    throw new Error(`blocked_host: refusing to fetch non-public host "${input}"`);
  }

  // Last-resort catch-all: the parser must agree with what we were handed.
  // Anything that survives the character check but still reparses into a
  // DIFFERENT host is the class of trick this function exists to stop, so treat
  // disagreement as hostile rather than trying to enumerate the tricks.
  //
  // Two legitimate transformations are exempt, or this would reject real hosts:
  //   - IDN punycoding (münchen.de → xn--mnchen-3ya.de). Every attack shape
  //     above is ASCII, so skipping non-ASCII costs the guard nothing.
  //   - IPv6 canonicalization ([2001:0db8::1] → [2001:db8::1]). The address is
  //     already fully validated above, where it matters.
  const asciiOnly = !/[^\x20-\x7E]/.test(stripped);
  const isV6Literal = stripped.startsWith('[');
  const expected = stripped.toLowerCase().replace(/:\d+$/, '');
  if (asciiOnly && !isV6Literal && u.hostname !== expected) {
    throw new Error(
      `blocked_host: ${label} "${input}" did not parse as the hostname it appears to be (got "${u.hostname}").`,
    );
  }

  return u.host;
}

/**
 * Validate a single DNS LABEL that a pack interpolates before a FIXED suffix
 * (`https://${sub}.freshdesk.com`, `https://${region}.api.riotgames.com`).
 *
 * A different problem from assertPublicHostname, and stricter: because the
 * suffix is fixed, the only escape is a character that ends the label early, so
 * a positive charset is both sufficient and simpler than parsing. Do NOT swap
 * these two — validating a label with assertPublicHostname would accept dots
 * and a port, and validating a hostname with this would reject every real one.
 *
 * These packs send credentials, so a label that escapes the suffix is a key
 * leak, not just an SSRF.
 */
function assertHostLabel(raw: unknown, label = 'subdomain'): string {
  const v = typeof raw === 'string' ? raw.trim() : '';
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(v)) {
    throw new Error(
      `blocked_host: ${label} "${v}" must be a bare DNS label — letters, digits and hyphens only (e.g. "mycompany").`,
    );
  }
  return v.toLowerCase();
}

/**
 * Fetch a URL with SSRF protection that ALSO covers redirects.
 *
 * A plain `fetch(url)` uses `redirect: 'follow'`, which silently defeats an
 * `isPublicHttpUrl()` pre-check: a public URL can return a 3xx to a private /
 * loopback / metadata host and the runtime follows it without re-validation
 * (and a hostname can resolve to a private address regardless). safeFetch
 * validates the initial URL AND every redirect hop — it fetches with
 * `redirect: 'manual'`, re-runs isPublicHttpUrl on each `Location`, and
 * refuses to follow a hop to a non-public / non-https target.
 *
 * Throws `blocked_url: …` if the initial URL or any hop is unsafe, or if the
 * redirect budget is exceeded. Callers already wrap probes in try/catch, so a
 * blocked redirect flows through their normal failure path (submission stays
 * pending, monitor records a down check, introspection error, etc.).
 *
 * Method + body from `init` are preserved across hops (every hop is validated,
 * so re-issuing the request to a vetted public host is safe); any caller-set
 * `redirect` is overridden to 'manual'.
 *
 * Credential headers are DROPPED on a cross-origin hop. Built-in fetch does
 * this for you; a manual redirect loop has to do it by hand, and skipping it
 * turns "public host redirects us somewhere" into "public host harvests our
 * Authorization header" — the initial host chooses the Location, so it chooses
 * where the credential goes.
 */
const CREDENTIAL_HEADERS = ['authorization', 'cookie', 'x-api-key', 'proxy-authorization'];

/** Strip credential headers from `init`, used when a redirect crosses origins. */
function stripCredentials(init: RequestInit | undefined): RequestInit | undefined {
  if (!init?.headers) return init;
  const h = new Headers(init.headers as HeadersInit);
  let removed = false;
  for (const name of CREDENTIAL_HEADERS) {
    if (h.has(name)) {
      h.delete(name);
      removed = true;
    }
  }
  return removed ? { ...init, headers: h } : init;
}

async function safeFetch(
  raw: string,
  init?: RequestInit,
  opts?: { maxRedirects?: number },
): Promise<Response> {
  const maxRedirects = opts?.maxRedirects ?? 3;
  const origin = assertPublicHttpUrl(raw).origin;
  let target = assertPublicHttpUrl(raw).toString();
  let reqInit = init;
  for (let hop = 0; ; hop++) {
    const res = await fetch(target, { ...reqInit, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    if (hop >= maxRedirects) throw new Error(`blocked_url: too many redirects (>${maxRedirects})`);
    let next: string;
    try {
      // Resolve relative Location against the current target before validating.
      next = new URL(location, target).toString();
    } catch {
      throw new Error('blocked_url: invalid redirect location');
    }
    if (!isPublicHttpUrl(next)) throw new Error('blocked_url: redirect to non-public URL');
    if (new URL(next).origin !== origin) reqInit = stripCredentials(reqInit);
    target = next;
  }
}


/**
 * Service status / uptime MCP — Atlassian Statuspage v2.
 *
 * Hundreds of vendors expose the same JSON contract at
 * https://<status-host>/api/v2/{status,summary,incidents,components}.json.
 * Every host in VENDORS below was verified with a real request that returned a
 * parseable Statuspage v2 payload (status.json + summary.json + incidents.json);
 * candidates that failed were dropped rather than guessed in.
 */


const UA = 'pipeworx-mcp-statuspage/1.0 (+https://pipeworx.io)';
const TIMEOUT_MS = 12000;

interface Vendor {
  host: string;
  name: string;
  category: 'ai' | 'cloud' | 'data' | 'devtools' | 'payments' | 'comms' | 'saas';
  aliases?: string[];
  /** Host serves status/summary/incidents but omits /incidents/unresolved.json — open incidents are derived instead. */
  lite?: boolean;
}

/** Verified Atlassian Statuspage hosts. Do not add an entry without a real successful request. */
const VENDORS: Record<string, Vendor> = {
  '1password': { host: 'status.1password.com', name: '1Password', category: 'saas', aliases: ['onepassword', '1 password'] },
  ably: { host: 'status.ably.com', name: 'Ably', category: 'comms' },
  airtable: { host: 'status.airtable.com', name: 'Airtable', category: 'saas', aliases: ['air table'] },
  akamai: { host: 'www.akamaistatus.com', name: 'Akamai', category: 'cloud' },
  alchemy: { host: 'status.alchemy.com', name: 'Alchemy', category: 'payments' },
  alpaca: { host: 'status.alpaca.markets', name: 'Alpaca', category: 'payments', aliases: ['alpaca markets'] },
  amplitude: { host: 'status.amplitude.com', name: 'Amplitude', category: 'data' },
  anthropic: { host: 'status.claude.com', name: 'Anthropic (Claude)', category: 'ai', aliases: ['claude', 'claude ai'] },
  assemblyai: { host: 'status.assemblyai.com', name: 'AssemblyAI', category: 'ai', aliases: ['assembly ai'] },
  atlassian: { host: 'status.atlassian.com', name: 'Atlassian', category: 'devtools' },
  auth0: { host: 'auth0.statuspage.io', name: 'Auth0', category: 'saas', aliases: ['auth zero'] },
  bandwidth: { host: 'status.bandwidth.com', name: 'Bandwidth', category: 'comms' },
  bigcommerce: { host: 'status.bigcommerce.com', name: 'BigCommerce', category: 'payments', aliases: ['big commerce'] },
  bitbucket: { host: 'bitbucket.status.atlassian.com', name: 'Bitbucket', category: 'devtools' },
  bitrise: { host: 'status.bitrise.io', name: 'Bitrise', category: 'devtools' },
  box: { host: 'status.box.com', name: 'Box', category: 'saas' },
  braze: { host: 'braze.statuspage.io', name: 'Braze', category: 'comms' },
  bunny: { host: 'status.bunny.net', name: 'bunny.net', category: 'cloud', aliases: ['bunnynet', 'bunny net', 'bunnycdn'] },
  chargebee: { host: 'status.chargebee.com', name: 'Chargebee', category: 'payments', aliases: ['charge bee'] },
  circle: { host: 'status.circle.com', name: 'Circle', category: 'payments', aliases: ['circle usdc', 'usdc'] },
  circleci: { host: 'status.circleci.com', name: 'CircleCI', category: 'devtools', aliases: ['circle ci'] },
  clerk: { host: 'status.clerk.com', name: 'Clerk', category: 'saas', aliases: ['clerk dev'], lite: true },
  cloudflare: { host: 'www.cloudflarestatus.com', name: 'Cloudflare', category: 'cloud', aliases: ['cf'] },
  cloudinary: { host: 'status.cloudinary.com', name: 'Cloudinary', category: 'cloud' },
  cockroachdb: { host: 'status.cockroachlabs.cloud', name: 'CockroachDB Cloud', category: 'data', aliases: ['cockroach', 'cockroach labs'] },
  cohere: { host: 'status.cohere.com', name: 'Cohere', category: 'ai', lite: true },
  coinbase: { host: 'status.coinbase.com', name: 'Coinbase', category: 'payments' },
  confluence: { host: 'confluence.status.atlassian.com', name: 'Confluence', category: 'devtools' },
  confluent: { host: 'status.confluent.cloud', name: 'Confluent Cloud', category: 'data', aliases: ['kafka confluent'] },
  contentful: { host: 'www.contentfulstatus.com', name: 'Contentful', category: 'saas' },
  crates: { host: 'status.crates.io', name: 'Rust / crates.io', category: 'devtools', aliases: ['cratesio', 'rust crates', 'rust'] },
  cursor: { host: 'status.cursor.com', name: 'Cursor', category: 'ai', aliases: ['cursor ide'] },
  datadog: { host: 'status.datadoghq.com', name: 'Datadog (US1)', category: 'data', aliases: ['datadoghq'] },
  dbt: { host: 'status.getdbt.com', name: 'dbt Cloud', category: 'data', aliases: ['dbt cloud', 'dbt labs'], lite: true },
  deepgram: { host: 'status.deepgram.com', name: 'Deepgram', category: 'ai', aliases: ['deep gram'] },
  digitalocean: { host: 'status.digitalocean.com', name: 'DigitalOcean', category: 'cloud', aliases: ['digital ocean'] },
  discord: { host: 'discordstatus.com', name: 'Discord', category: 'comms' },
  docusign: { host: 'status.docusign.com', name: 'Docusign', category: 'saas', aliases: ['docu sign'] },
  dropbox: { host: 'status.dropbox.com', name: 'Dropbox', category: 'saas', aliases: ['drop box'] },
  duo: { host: 'status.duo.com', name: 'Duo Security', category: 'saas', aliases: ['duo security', 'cisco duo'] },
  elastic: { host: 'status.elastic.co', name: 'Elastic Cloud', category: 'data', aliases: ['elasticsearch', 'elastic cloud'] },
  elevenlabs: { host: 'status.elevenlabs.io', name: 'ElevenLabs', category: 'ai', aliases: ['eleven labs', '11labs'], lite: true },
  epicgames: { host: 'status.epicgames.com', name: 'Epic Games', category: 'saas', aliases: ['epic games', 'epic', 'fortnite'] },
  fastspring: { host: 'status.fastspring.com', name: 'FastSpring', category: 'payments', aliases: ['fast spring'] },
  figma: { host: 'status.figma.com', name: 'Figma', category: 'saas' },
  fireworks: { host: 'status.fireworks.ai', name: 'Fireworks AI', category: 'ai', aliases: ['fireworks ai'], lite: true },
  fly: { host: 'status.flyio.net', name: 'Fly.io', category: 'cloud', aliases: ['flyio', 'fly io'] },
  'gemini-exchange': { host: 'status.gemini.com', name: 'Gemini Exchange', category: 'payments', aliases: ['gemini'] },
  github: { host: 'www.githubstatus.com', name: 'GitHub', category: 'devtools', aliases: ['gh'] },
  godaddy: { host: 'status.godaddy.com', name: 'GoDaddy', category: 'cloud', aliases: ['go daddy'] },
  grafana: { host: 'status.grafana.com', name: 'Grafana Cloud', category: 'data', aliases: ['grafana cloud'] },
  groq: { host: 'groqstatus.com', name: 'Groq', category: 'ai', aliases: ['groqcloud'], lite: true },
  hashicorp: { host: 'status.hashicorp.com', name: 'HashiCorp', category: 'devtools', aliases: ['terraform', 'vault', 'consul', 'nomad'], lite: true },
  heap: { host: 'status.heap.io', name: 'Heap', category: 'data' },
  hubspot: { host: 'status.hubspot.com', name: 'HubSpot', category: 'saas', aliases: ['hub spot'] },
  imgix: { host: 'status.imgix.com', name: 'imgix', category: 'cloud' },
  infura: { host: 'status.infura.io', name: 'Infura', category: 'payments' },
  jfrog: { host: 'status.jfrog.io', name: 'JFrog Cloud', category: 'devtools', aliases: ['artifactory'] },
  jira: { host: 'jira-software.status.atlassian.com', name: 'Jira', category: 'devtools', aliases: ['jira software'] },
  klaviyo: { host: 'status.klaviyo.com', name: 'Klaviyo', category: 'comms' },
  kraken: { host: 'status.kraken.com', name: 'Kraken', category: 'payments' },
  launchdarkly: { host: 'status.launchdarkly.com', name: 'LaunchDarkly', category: 'devtools', aliases: ['launch darkly'] },
  linode: { host: 'status.linode.com', name: 'Linode', category: 'cloud', aliases: ['akamai linode'] },
  loom: { host: 'loom.status.atlassian.com', name: 'Loom', category: 'devtools' },
  mailgun: { host: 'status.mailgun.com', name: 'Mailgun', category: 'comms' },
  mapbox: { host: 'status.mapbox.com', name: 'Mapbox', category: 'cloud', aliases: ['map box'] },
  marqeta: { host: 'status.marqeta.com', name: 'Marqeta', category: 'payments' },
  miro: { host: 'status.miro.com', name: 'Miro', category: 'saas', lite: true },
  mixpanel: { host: 'www.mixpanelstatus.com', name: 'Mixpanel', category: 'data', aliases: ['mix panel'] },
  mongodb: { host: 'status.mongodb.com', name: 'MongoDB Cloud', category: 'data', aliases: ['atlas', 'mongo', 'mongodb atlas'] },
  netlify: { host: 'www.netlifystatus.com', name: 'Netlify', category: 'cloud' },
  newrelic: { host: 'status.newrelic.com', name: 'New Relic', category: 'data', aliases: ['new relic'] },
  ngrok: { host: 'status.ngrok.com', name: 'ngrok', category: 'cloud' },
  npm: { host: 'status.npmjs.org', name: 'npm', category: 'devtools', aliases: ['npmjs', 'node package manager'] },
  nylas: { host: 'status-v3.nylas.com', name: 'Nylas', category: 'comms' },
  openai: { host: 'status.openai.com', name: 'OpenAI', category: 'ai', aliases: ['chatgpt', 'open ai', 'gpt'], lite: true },
  opsgenie: { host: 'opsgenie.status.atlassian.com', name: 'Opsgenie', category: 'devtools' },
  optimizely: { host: 'status.optimizely.com', name: 'Optimizely', category: 'data' },
  pantheon: { host: 'status.pantheon.io', name: 'Pantheon', category: 'cloud' },
  pinecone: { host: 'status.pinecone.io', name: 'Pinecone', category: 'ai', aliases: ['pine cone'] },
  plaid: { host: 'status.plaid.com', name: 'Plaid', category: 'payments', lite: true },
  planetscale: { host: 'www.planetscalestatus.com', name: 'PlanetScale', category: 'data', aliases: ['planet scale'], lite: true },
  postman: { host: 'status.postman.com', name: 'Postman', category: 'devtools' },
  pusher: { host: 'status.pusher.com', name: 'Pusher', category: 'comms' },
  pypi: { host: 'status.python.org', name: 'Python Infrastructure (PyPI)', category: 'devtools', aliases: ['python', 'python infrastructure'] },
  quickbooks: { host: 'status.developer.intuit.com', name: 'Intuit Developer (QuickBooks)', category: 'payments', aliases: ['intuit', 'intuit developer'] },
  quicknode: { host: 'status.quicknode.com', name: 'QuickNode', category: 'payments', aliases: ['quick node'] },
  readme: { host: 'www.readmestatus.com', name: 'ReadMe', category: 'devtools', aliases: ['readme io'] },
  recurly: { host: 'status.recurly.com', name: 'Recurly', category: 'payments', lite: true },
  reddit: { host: 'www.redditstatus.com', name: 'Reddit', category: 'saas' },
  render: { host: 'status.render.com', name: 'Render', category: 'cloud' },
  replicate: { host: 'www.replicatestatus.com', name: 'Replicate', category: 'ai', lite: true },
  rubygems: { host: 'status.rubygems.org', name: 'RubyGems.org', category: 'devtools', aliases: ['ruby gems'] },
  sanity: { host: 'www.sanity-status.com', name: 'Sanity', category: 'saas', aliases: ['sanity io'] },
  segment: { host: 'status.segment.com', name: 'Segment', category: 'data', aliases: ['twilio segment'] },
  sendgrid: { host: 'status.sendgrid.com', name: 'SendGrid', category: 'comms', aliases: ['twilio sendgrid'] },
  sentry: { host: 'status.sentry.io', name: 'Sentry', category: 'data' },
  shopify: { host: 'www.shopifystatus.com', name: 'Shopify', category: 'payments' },
  smartsheet: { host: 'status.smartsheet.com', name: 'Smartsheet', category: 'saas' },
  snowflake: { host: 'status.snowflake.com', name: 'Snowflake', category: 'data' },
  snyk: { host: 'status.snyk.io', name: 'Snyk', category: 'devtools' },
  square: { host: 'www.issquareup.com', name: 'Square', category: 'payments', aliases: ['squareup'], lite: true },
  squarespace: { host: 'status.squarespace.com', name: 'Squarespace', category: 'saas' },
  stability: { host: 'status.stability.ai', name: 'Stability AI', category: 'ai', aliases: ['stability ai', 'stable diffusion'], lite: true },
  statuscake: { host: 'status.statuscake.com', name: 'StatusCake', category: 'devtools' },
  statuspage: { host: 'metastatuspage.com', name: 'Atlassian Statuspage', category: 'devtools', aliases: ['atlassian statuspage'] },
  supabase: { host: 'status.supabase.com', name: 'Supabase', category: 'data' },
  tailscale: { host: 'status.tailscale.com', name: 'Tailscale', category: 'cloud', aliases: ['tail scale'], lite: true },
  temporal: { host: 'status.temporal.io', name: 'Temporal Cloud', category: 'devtools', aliases: ['temporal io'] },
  travisci: { host: 'www.traviscistatus.com', name: 'Travis CI', category: 'devtools', aliases: ['travis', 'travis ci'] },
  trello: { host: 'trello.status.atlassian.com', name: 'Trello', category: 'devtools' },
  twilio: { host: 'status.twilio.com', name: 'Twilio', category: 'comms' },
  twitch: { host: 'status.twitch.com', name: 'Twitch', category: 'saas' },
  typeform: { host: 'status.typeform.com', name: 'Typeform', category: 'saas' },
  upstash: { host: 'status.upstash.com', name: 'Upstash', category: 'cloud' },
  vercel: { host: 'www.vercel-status.com', name: 'Vercel', category: 'cloud' },
  vimeo: { host: 'www.vimeostatus.com', name: 'Vimeo', category: 'saas' },
  webflow: { host: 'status.webflow.com', name: 'Webflow', category: 'saas' },
  wise: { host: 'status.wise.com', name: 'Wise', category: 'payments', aliases: ['transferwise'] },
  workos: { host: 'status.workos.com', name: 'WorkOS', category: 'saas', aliases: ['work os'] },
  xero: { host: 'status.xero.com', name: 'Xero', category: 'payments' },
  zapier: { host: 'status.zapier.com', name: 'Zapier', category: 'saas', lite: true },
  zoom: { host: 'www.zoomstatus.com', name: 'Zoom', category: 'comms' },
};

/**
 * Vendors probed that publish status somewhere else entirely — no Statuspage v2 JSON.
 * Kept so an agent asking "is AWS down" gets the real status URL instead of a shrug.
 */
const ELSEWHERE: Record<string, { name: string; status_url: string }> = {
  adyen: { name: 'Adyen', status_url: 'https://status.adyen.com/' },
  algolia: { name: 'Algolia', status_url: 'https://status.algolia.com/' },
  asana: { name: 'Asana', status_url: 'https://trust.asana.com/' },
  aws: { name: 'Amazon Web Services', status_url: 'https://health.aws.amazon.com/health/status' },
  azure: { name: 'Microsoft Azure', status_url: 'https://azure.status.microsoft/' },
  bitwarden: { name: 'Bitwarden', status_url: 'https://status.bitwarden.com/' },
  braintree: { name: 'Braintree', status_url: 'https://status.braintreepayments.com/' },
  calendly: { name: 'Calendly', status_url: 'https://status.calendly.com/' },
  codesandbox: { name: 'CodeSandbox', status_url: 'https://status.codesandbox.io/' },
  databricks: { name: 'Databricks', status_url: 'https://status.databricks.com/' },
  docker: { name: 'Docker', status_url: 'https://www.dockerstatus.com/' },
  fastly: { name: 'Fastly', status_url: 'https://status.fastly.com/' },
  firebase: { name: 'Firebase', status_url: 'https://status.firebase.google.com/' },
  gcp: { name: 'Google Cloud', status_url: 'https://status.cloud.google.com/' },
  gitlab: { name: 'GitLab', status_url: 'https://status.gitlab.com/' },
  heroku: { name: 'Heroku', status_url: 'https://status.heroku.com/' },
  huggingface: { name: 'Hugging Face', status_url: 'https://status.huggingface.co/' },
  intercom: { name: 'Intercom', status_url: 'https://www.intercomstatus.com/' },
  jetbrains: { name: 'JetBrains', status_url: 'https://status.jetbrains.com/' },
  linear: { name: 'Linear', status_url: 'https://status.linear.app/' },
  mailchimp: { name: 'Mailchimp', status_url: 'https://status.mailchimp.com/' },
  meilisearch: { name: 'Meilisearch', status_url: 'https://status.meilisearch.com/' },
  mistral: { name: 'Mistral AI', status_url: 'https://status.mistral.ai/' },
  modal: { name: 'Modal', status_url: 'https://status.modal.com/' },
  neon: { name: 'Neon', status_url: 'https://neonstatus.com/' },
  notion: { name: 'Notion', status_url: 'https://status.notion.so/' },
  okta: { name: 'Okta', status_url: 'https://status.okta.com/' },
  openrouter: { name: 'OpenRouter', status_url: 'https://status.openrouter.ai/' },
  pagerduty: { name: 'PagerDuty', status_url: 'https://status.pagerduty.com/' },
  paypal: { name: 'PayPal', status_url: 'https://www.paypal-status.com/' },
  perplexity: { name: 'Perplexity', status_url: 'https://status.perplexity.ai/' },
  postmark: { name: 'Postmark', status_url: 'https://status.postmarkapp.com/' },
  railway: { name: 'Railway', status_url: 'https://status.railway.app/' },
  redis: { name: 'Redis Cloud', status_url: 'https://status.redis.io/' },
  replit: { name: 'Replit', status_url: 'https://status.replit.com/' },
  salesforce: { name: 'Salesforce', status_url: 'https://status.salesforce.com/' },
  slack: { name: 'Slack', status_url: 'https://slack-status.com/' },
  sourcegraph: { name: 'Sourcegraph', status_url: 'https://sourcegraph.statuspage.io/' },
  stripe: { name: 'Stripe', status_url: 'https://status.stripe.com/' },
  together: { name: 'Together AI', status_url: 'https://status.together.ai/' },
  unity: { name: 'Unity', status_url: 'https://status.unity.com/' },
  vultr: { name: 'Vultr', status_url: 'https://status.vultr.com/' },
  zendesk: { name: 'Zendesk', status_url: 'https://status.zendesk.com/' },
};

const VENDOR_COUNT = Object.keys(VENDORS).length;

const INDICATOR_MEANING: Record<string, string> = {
  none: 'all systems operational',
  minor: 'minor issue — some services degraded',
  major: 'major outage affecting multiple services',
  critical: 'critical outage',
  maintenance: 'scheduled maintenance in progress',
};

// ── tools ───────────────────────────────────────────────────────────

const tools: McpToolExport['tools'] = [
  {
    name: 'statuspage_check',
    description:
      `Is a service down right now? Live service status, outage and uptime check for ${VENDOR_COUNT} vendors that publish an Atlassian Statuspage — OpenAI, Anthropic/Claude, GitHub, Cloudflare, Vercel, Netlify, DigitalOcean, MongoDB, Snowflake, Datadog, Twilio, SendGrid, Zoom, Discord, Shopify, Coinbase, Plaid, Figma, Dropbox, Atlassian/Jira and more. Returns the current status indicator (none / minor / major / critical / maintenance), the vendor's own status line such as "All Systems Operational" or "Partial System Outage", every component currently degraded or offline, open incidents with their latest update text and how long they have been running, and upcoming scheduled maintenance where the page publishes it. Use for questions about downtime, outages, service health, incidents in progress and whether an API or platform is working. Pass status_host to check any other vendor running a Statuspage.`,
    inputSchema: {
      type: 'object',
      properties: {
        vendor: { type: 'string', description: 'Vendor name or key, forgiving about case and spacing: "openai", "OpenAI", "open ai", "github", "claude", "cloudflare". Call statuspage_list_vendors for the full covered set.' },
        status_host: { type: 'string', description: 'Statuspage hostname to query directly, e.g. "status.somevendor.com". Use for any vendor outside the curated map. Overrides vendor when both are given.' },
        include_components: { type: 'boolean', description: 'Include every component and its status, rather than only the degraded ones (default false).' },
      },
    },
  },
  {
    name: 'statuspage_incidents',
    description:
      `Incident and outage history for a vendor's status page — what broke, when, and whether it is fixed. Covers ${VENDOR_COUNT} verified Atlassian Statuspage vendors across AI providers, clouds, developer platforms, payments and communications. Each incident returns its title, lifecycle status (investigating / identified / monitoring / resolved), impact level (none / minor / major / critical), the time it started, the time it resolved, how long it lasted, the affected components, and the text of the latest update the vendor posted. Set unresolved_only to see only incidents that are still open. Use for outage history, past downtime, current incidents and postmortem timelines. Pass status_host for vendors outside the curated map.`,
    inputSchema: {
      type: 'object',
      properties: {
        vendor: { type: 'string', description: 'Vendor name or key, e.g. "cloudflare", "github", "anthropic".' },
        status_host: { type: 'string', description: 'Statuspage hostname to query directly, e.g. "status.somevendor.com". Overrides vendor when both are given.' },
        unresolved_only: { type: 'boolean', description: 'Return only incidents that are still open (default false).' },
        limit: { type: 'number', description: 'Maximum incidents to return, 1-50 (default 10).' },
        include_all_updates: { type: 'boolean', description: 'Include the full update timeline for each incident rather than only the latest update (default false).' },
      },
    },
  },
  {
    name: 'statuspage_list_vendors',
    description:
      `Which companies this service-status pack can answer for: ${VENDOR_COUNT} verified Atlassian Statuspage hosts across AI and model providers, cloud and hosting, databases and observability, developer tools, payments and fintech, communications, and business SaaS. Returns the total count plus each vendor's lookup key, display name, category and status hostname, so a vendor name can be confirmed before calling statuspage_check instead of guessed. Also lists well-known companies whose status pages use a different format, together with the URL a human should open. Filter by category or search text.`,
    inputSchema: {
      type: 'object',
      properties: {
        category: { type: 'string', description: 'Restrict to one category: ai, cloud, data, devtools, payments, comms, saas.', enum: ['ai', 'cloud', 'data', 'devtools', 'payments', 'comms', 'saas'] },
        query: { type: 'string', description: 'Substring filter over vendor key, display name and aliases, e.g. "cloud" or "git".' },
        include_elsewhere: { type: 'boolean', description: 'Also list known vendors that publish status in another format, with the URL to open (default false).' },
      },
    },
  },
  {
    name: 'statuspage_multi_check',
    description:
      'Check the live service status of several vendors at once — "are any of my providers down right now?". Takes a list of vendor names or Statuspage hostnames and returns one compact row each: status indicator, the vendor\'s status line, open incident count and degraded component count, plus a roll-up naming which are operational, which are degraded or in an outage, and which could not be reached. Use for dependency health sweeps, incident triage across a stack, and monitoring a set of upstream APIs in one call.',
    inputSchema: {
      type: 'object',
      properties: {
        vendors: {
          type: 'array',
          description: 'Vendor names/keys, or bare Statuspage hostnames (anything containing a dot is treated as a host). 1-20 entries, e.g. ["openai", "anthropic", "github", "cloudflare"].',
          items: { type: 'string' },
        },
      },
      required: ['vendors'],
    },
  },
];

// ── resolution ──────────────────────────────────────────────────────

function norm(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '');
}

let INDEX: Map<string, string> | null = null;
function index(): Map<string, string> {
  if (INDEX) return INDEX;
  const m = new Map<string, string>();
  for (const [slug, v] of Object.entries(VENDORS)) {
    for (const k of [slug, v.name, ...(v.aliases ?? [])]) {
      const n = norm(k);
      if (n && !m.has(n)) m.set(n, slug);
    }
  }
  INDEX = m;
  return m;
}

function resolveVendor(input: string): string | null {
  return index().get(norm(input)) ?? null;
}

function nearMatches(input: string, max = 6): string[] {
  const n = norm(input);
  if (!n) return [];
  const hits = new Set<string>();
  for (const [key, slug] of index()) {
    if (key.startsWith(n) || n.startsWith(key) || key.includes(n) || n.includes(key)) hits.add(slug);
  }
  if (hits.size === 0 && n.length >= 4) {
    // last resort: share a 4-char run
    for (const [key, slug] of index()) {
      for (let i = 0; i + 4 <= n.length; i++) if (key.includes(n.slice(i, i + 4))) { hits.add(slug); break; }
    }
  }
  return [...hits].slice(0, max);
}

function cleanHost(raw: string): string {
  // Truncating a pasted path is deliberate and safe here — this pack's charset
  // rule below rejects everything that could survive it — so the friendly
  // behaviour stays. What changed (fleet #214) is WHO decides public vs
  // private: assertPublicHostname instead of the local BAD_HOST regex, which
  // missed CGNAT 100.64/10 and IPv4-mapped IPv6.
  const h = raw.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').replace(/:\d+$/, '').toLowerCase();
  if (!h || !/^[a-z0-9.-]+$/.test(h) || !h.includes('.')) {
    throw new Error(`user_error: status_host "${raw}" is not a usable public hostname. Pass something like "status.somevendor.com".`);
  }
  try {
    return assertPublicHostname(h, 'status_host');
  } catch {
    throw new Error(`user_error: status_host "${raw}" is not a usable public hostname. Pass something like "status.somevendor.com".`);
  }
}

interface Target { host: string; name: string; slug: string | null; source: 'curated_map' | 'caller_supplied_host'; lite: boolean }

/** Returns a Target, or a not-found envelope the caller should return verbatim. */
function target(args: Record<string, unknown>): Target | Record<string, unknown> {
  const host = typeof args.status_host === 'string' && args.status_host.trim() ? args.status_host : null;
  if (host) {
    const h = cleanHost(host);
    return { host: h, name: h, slug: null, source: 'caller_supplied_host', lite: false };
  }
  const vendor = typeof args.vendor === 'string' ? args.vendor.trim() : '';
  if (!vendor) {
    return {
      found: false,
      reason: 'no_vendor_given',
      hint: `Pass vendor (one of ${VENDOR_COUNT} covered names, e.g. "openai", "github", "cloudflare") or status_host (e.g. "status.somevendor.com"). Call statuspage_list_vendors for the full list.`,
    };
  }
  const slug = resolveVendor(vendor);
  if (!slug) {
    const alt = ELSEWHERE[norm(vendor)] ?? Object.entries(ELSEWHERE).find(([k]) => norm(k) === norm(vendor))?.[1];
    if (alt) {
      return {
        found: false,
        reason: 'vendor_not_statuspage',
        query: vendor,
        vendor_name: alt.name,
        status_url: alt.status_url,
        hint: `${alt.name} publishes status at ${alt.status_url}, which does not serve the Atlassian Statuspage v2 JSON this pack reads. Open that URL, or pass status_host if you know a Statuspage host for it.`,
      };
    }
    const near = nearMatches(vendor);
    return {
      found: false,
      reason: 'vendor_not_covered',
      query: vendor,
      did_you_mean: near.map((s) => ({ vendor: s, name: VENDORS[s]!.name, status_host: VENDORS[s]!.host })),
      covered_vendor_count: VENDOR_COUNT,
      hint: `"${vendor}" is not in the curated map of ${VENDOR_COUNT} verified Statuspage vendors. Call statuspage_list_vendors to see the full set, or pass status_host if you know this vendor's Statuspage hostname (e.g. "status.${norm(vendor)}.com").`,
    };
  }
  const v = VENDORS[slug]!;
  return { host: v.host, name: v.name, slug, source: 'curated_map', lite: v.lite === true };
}

function isTarget(t: Target | Record<string, unknown>): t is Target {
  return typeof (t as Target).host === 'string' && 'source' in t;
}

// ── fetch ───────────────────────────────────────────────────────────

class Unreachable extends Error {}

async function getJson(host: string, path: string): Promise<any> {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(`https://${host}${path}`, {
      headers: { Accept: 'application/json', 'User-Agent': UA },
      signal: ctl.signal,
      redirect: 'follow',
    });
    if (!res.ok) throw new Unreachable(`HTTP ${res.status} from https://${host}${path}`);
    const text = await res.text();
    try {
      return JSON.parse(text);
    } catch {
      throw new Unreachable(`https://${host}${path} returned a non-JSON body (${text.slice(0, 60).replace(/\s+/g, ' ')}…) — this host is probably not an Atlassian Statuspage.`);
    }
  } catch (e) {
    if (e instanceof Unreachable) throw e;
    throw new Unreachable(`Could not reach https://${host}${path}: ${(e as Error).message}`);
  } finally {
    clearTimeout(timer);
  }
}

function unreachable(t: Target, err: unknown): Record<string, unknown> {
  return {
    found: false,
    reason: 'status_page_unreachable',
    vendor: t.slug,
    vendor_name: t.name,
    status_host: t.host,
    source: t.source,
    error: (err as Error).message,
    hint: 'The status page itself could not be read, so nothing is known about this vendor right now. This is a failure to check, which is different from a vendor reporting no incidents.',
  };
}

// ── shaping ─────────────────────────────────────────────────────────

const OPEN_STATES = new Set(['investigating', 'identified', 'monitoring']);

function ago(iso: string | null | undefined, now: number): string | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return null;
  const mins = Math.max(0, Math.round((now - t) / 60000));
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

function durationMinutes(start?: string | null, end?: string | null): number | null {
  if (!start || !end) return null;
  const a = Date.parse(start), b = Date.parse(end);
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.max(0, Math.round((b - a) / 60000));
}

function shapeIncident(i: any, now: number, allUpdates: boolean): Record<string, unknown> {
  const updates: any[] = Array.isArray(i?.incident_updates) ? i.incident_updates : [];
  const latest = updates[0];
  const started = i?.started_at ?? i?.created_at ?? null;
  const out: Record<string, unknown> = {
    id: i?.id ?? null,
    name: i?.name ?? null,
    status: i?.status ?? null,
    open: OPEN_STATES.has(String(i?.status)),
    impact: i?.impact ?? null,
    started_at: started,
    started_ago: ago(started, now),
    resolved_at: i?.resolved_at ?? null,
    duration_minutes: durationMinutes(started, i?.resolved_at ?? null),
    url: i?.shortlink ?? null,
    affected_components: [
      ...new Set(
        updates.flatMap((u) => (Array.isArray(u?.affected_components) ? u.affected_components.map((c: any) => c?.name).filter(Boolean) : [])),
      ),
    ],
  };
  if (allUpdates) {
    out.updates = updates.map((u) => ({ status: u?.status ?? null, body: u?.body ?? null, created_at: u?.created_at ?? null }));
  } else if (latest) {
    out.latest_update = { status: latest.status ?? null, body: latest.body ?? null, created_at: latest.created_at ?? null, created_ago: ago(latest.created_at, now) };
  }
  return out;
}

function shapeComponent(c: any): Record<string, unknown> {
  return {
    name: c?.name ?? null,
    status: c?.status ?? null,
    is_group: c?.group === true,
    description: c?.description ?? null,
  };
}

/** Open incidents, preferring /incidents/unresolved.json and falling back to filtering the incident feed. */
async function openIncidents(host: string, fromSummary: any): Promise<{ incidents: any[]; via: string }> {
  if (Array.isArray(fromSummary)) return { incidents: fromSummary, via: 'summary.json' };
  try {
    const j = await getJson(host, '/api/v2/incidents/unresolved.json');
    if (Array.isArray(j?.incidents)) return { incidents: j.incidents, via: 'incidents/unresolved.json' };
  } catch {
    /* host omits the unresolved endpoint — derive below */
  }
  const j = await getJson(host, '/api/v2/incidents.json');
  const all: any[] = Array.isArray(j?.incidents) ? j.incidents : [];
  return { incidents: all.filter((i) => OPEN_STATES.has(String(i?.status))), via: 'incidents.json (filtered to open)' };
}

// ── handlers ────────────────────────────────────────────────────────

async function checkOne(t: Target, includeComponents: boolean): Promise<Record<string, unknown>> {
  const now = Date.now();
  let summary: any;
  try {
    summary = await getJson(t.host, '/api/v2/summary.json');
  } catch (e) {
    try {
      // Some hosts serve status.json but not summary.json.
      const s = await getJson(t.host, '/api/v2/status.json');
      summary = { page: s?.page, status: s?.status, components: [] };
    } catch {
      return unreachable(t, e);
    }
  }
  const status = summary?.status ?? {};
  const indicator = typeof status.indicator === 'string' ? status.indicator : null;
  if (!indicator || !summary?.page) {
    return {
      found: false,
      reason: 'status_page_unreachable',
      vendor: t.slug,
      vendor_name: t.name,
      status_host: t.host,
      source: t.source,
      error: `https://${t.host}/api/v2/summary.json responded, but not with an Atlassian Statuspage v2 payload.`,
      hint: 'Confirm this host runs Atlassian Statuspage; its /api/v2/summary.json must return page + status objects.',
    };
  }

  const components: any[] = Array.isArray(summary.components) ? summary.components : [];
  const degraded = components.filter((c) => c?.status && c.status !== 'operational');

  let open: any[] = [];
  let incidentsVia = 'summary.json';
  try {
    const r = await openIncidents(t.host, summary.incidents);
    open = r.incidents;
    incidentsVia = r.via;
  } catch (e) {
    incidentsVia = `unavailable (${(e as Error).message.slice(0, 80)})`;
  }

  const maint: any[] = Array.isArray(summary.scheduled_maintenances) ? summary.scheduled_maintenances : [];

  const page = summary.page ?? {};
  return {
    found: true,
    vendor: t.slug,
    vendor_name: t.slug ? t.name : (page.name ?? t.host),
    status_host: t.host,
    source: t.source,
    coverage_note: t.source === 'curated_map'
      ? 'Host comes from this pack\'s curated map of verified Statuspage vendors.'
      : 'Host was supplied by the caller; this pack did not verify it in advance.',
    operational: indicator === 'none',
    indicator,
    indicator_meaning: INDICATOR_MEANING[indicator] ?? indicator,
    status: status.description ?? null,
    open_incident_count: open.length,
    open_incidents: open.map((i) => shapeIncident(i, now, false)),
    components_total: components.length,
    components_degraded_count: degraded.length,
    components_degraded: degraded.map(shapeComponent),
    ...(includeComponents ? { components: components.map(shapeComponent) } : {}),
    upcoming_maintenance_count: maint.length,
    upcoming_maintenance: maint.slice(0, 5).map((m) => ({
      name: m?.name ?? null,
      status: m?.status ?? null,
      scheduled_for: m?.scheduled_for ?? m?.started_at ?? null,
      scheduled_until: m?.scheduled_until ?? null,
    })),
    page_url: page.url ?? `https://${t.host}`,
    page_updated_at: page.updated_at ?? null,
    page_updated_ago: ago(page.updated_at, now),
    checked_at: new Date(now).toISOString(),
    incidents_source: incidentsVia,
  };
}

async function callTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case 'statuspage_check': {
      const t = target(args);
      if (!isTarget(t)) return t;
      return checkOne(t, args.include_components === true);
    }

    case 'statuspage_incidents': {
      const t = target(args);
      if (!isTarget(t)) return t;
      const now = Date.now();
      const unresolvedOnly = args.unresolved_only === true;
      const allUpdates = args.include_all_updates === true;
      const limit = Math.min(50, Math.max(1, Math.round(Number(args.limit) || 10)));

      let incidents: any[];
      let via: string;
      try {
        if (unresolvedOnly) {
          const r = await openIncidents(t.host, undefined);
          incidents = r.incidents;
          via = r.via;
        } else {
          const j = await getJson(t.host, '/api/v2/incidents.json');
          if (!Array.isArray(j?.incidents)) throw new Unreachable(`https://${t.host}/api/v2/incidents.json did not return an incidents array.`);
          incidents = j.incidents;
          via = 'incidents.json';
        }
      } catch (e) {
        return unreachable(t, e);
      }

      const openCount = incidents.filter((i) => OPEN_STATES.has(String(i?.status))).length;
      return {
        found: true,
        vendor: t.slug,
        vendor_name: t.name,
        status_host: t.host,
        source: t.source,
        unresolved_only: unresolvedOnly,
        returned: Math.min(incidents.length, limit),
        total_available: incidents.length,
        open_incident_count: openCount,
        no_open_incidents: openCount === 0,
        incidents: incidents.slice(0, limit).map((i) => shapeIncident(i, now, allUpdates)),
        incidents_source: via,
        page_url: `https://${t.host}`,
        checked_at: new Date(now).toISOString(),
        ...(incidents.length === 0
          ? { note: unresolvedOnly ? `${t.name} reports no open incidents right now.` : `${t.name}'s status page lists no incidents.` }
          : {}),
      };
    }

    case 'statuspage_list_vendors': {
      const cat = typeof args.category === 'string' ? args.category.toLowerCase() : null;
      const q = typeof args.query === 'string' ? norm(args.query) : '';
      let rows = Object.entries(VENDORS).map(([slug, v]) => ({
        vendor: slug,
        name: v.name,
        category: v.category,
        status_host: v.host,
        status_url: `https://${v.host}`,
        aliases: v.aliases ?? [],
      }));
      if (cat) rows = rows.filter((r) => r.category === cat);
      if (q) rows = rows.filter((r) => norm(r.vendor).includes(q) || norm(r.name).includes(q) || r.aliases.some((a) => norm(a).includes(q)));
      rows.sort((a, b) => a.vendor.localeCompare(b.vendor));

      const byCategory: Record<string, number> = {};
      for (const v of Object.values(VENDORS)) byCategory[v.category] = (byCategory[v.category] ?? 0) + 1;

      return {
        found: true,
        total_vendors: VENDOR_COUNT,
        returned: rows.length,
        ...(cat ? { category: cat } : {}),
        ...(typeof args.query === 'string' && args.query ? { query: args.query } : {}),
        by_category: byCategory,
        vendors: rows,
        coverage_note: `Every host listed here was verified with a live request returning an Atlassian Statuspage v2 payload. Any vendor outside this list can still be checked by passing status_host to statuspage_check.`,
        ...(args.include_elsewhere === true
          ? {
              status_published_elsewhere: Object.entries(ELSEWHERE)
                .map(([slug, e]) => ({ vendor: slug, name: e.name, status_url: e.status_url }))
                .filter((e) => !q || norm(e.vendor).includes(q) || norm(e.name).includes(q))
                .sort((a, b) => a.vendor.localeCompare(b.vendor)),
              elsewhere_note: 'These companies were probed and publish status in a format other than Atlassian Statuspage v2, so this pack reads their page URL rather than their data.',
            }
          : {}),
      };
    }

    case 'statuspage_multi_check': {
      const raw = args.vendors;
      if (!Array.isArray(raw) || raw.length === 0) {
        throw new Error('Required argument "vendors" is missing. Pass an array like ["openai", "anthropic", "github"].');
      }
      const wanted = raw.map((v) => String(v).trim()).filter(Boolean).slice(0, 20);

      // Resolve first, de-duplicating by host so two names for one page cost one request.
      const resolved: { input: string; t: Target | Record<string, unknown> }[] = wanted.map((input) => ({
        input,
        t: target(input.includes('.') && !resolveVendor(input) ? { status_host: input } : { vendor: input }),
      }));
      const byHost = new Map<string, Target>();
      for (const r of resolved) if (isTarget(r.t) && !byHost.has(r.t.host)) byHost.set(r.t.host, r.t);

      const hosts = [...byHost.values()];
      const results = new Map<string, Record<string, unknown>>();
      const queue = [...hosts];
      const worker = async () => {
        for (;;) {
          const t = queue.shift();
          if (!t) return;
          results.set(t.host, await checkOne(t, false));
        }
      };
      await Promise.all(Array.from({ length: Math.min(5, hosts.length) }, worker));

      const rows = resolved.map(({ input, t }) => {
        if (!isTarget(t)) return { requested: input, found: false, ...(t as Record<string, unknown>) };
        const r = results.get(t.host)!;
        if (r.found !== true) return { requested: input, ...r };
        return {
          requested: input,
          found: true,
          vendor: r.vendor,
          vendor_name: r.vendor_name,
          status_host: r.status_host,
          operational: r.operational,
          indicator: r.indicator,
          status: r.status,
          open_incident_count: r.open_incident_count,
          components_degraded_count: r.components_degraded_count,
          top_open_incident: Array.isArray(r.open_incidents) && r.open_incidents.length ? (r.open_incidents[0] as any).name : null,
          page_url: r.page_url,
        };
      });

      const okRows = rows.filter((r) => r.found === true);
      const degradedRows = okRows.filter((r) => (r as any).operational !== true);
      const unreachableRows = rows.filter((r) => (r as any).reason === 'status_page_unreachable');
      const unresolvedRows = rows.filter((r) => r.found !== true && (r as any).reason !== 'status_page_unreachable');
      const clean = degradedRows.length === 0 && unreachableRows.length === 0 && unresolvedRows.length === 0;
      const tail = [
        unreachableRows.length ? `${unreachableRows.length} status page${unreachableRows.length === 1 ? '' : 's'} could not be read` : '',
        unresolvedRows.length ? `${unresolvedRows.length} name${unresolvedRows.length === 1 ? '' : 's'} did not resolve to a covered vendor` : '',
      ].filter(Boolean);
      return {
        found: true,
        checked: rows.length,
        all_operational: clean,
        operational_count: okRows.length - degradedRows.length,
        degraded_count: degradedRows.length,
        unreachable_count: unreachableRows.length,
        unresolved_name_count: unresolvedRows.length,
        degraded: degradedRows.map((r) => ({ vendor_name: (r as any).vendor_name, indicator: (r as any).indicator, status: (r as any).status, open_incident_count: (r as any).open_incident_count })),
        results: rows,
        checked_at: new Date().toISOString(),
        summary: clean
          ? `All ${okRows.length} checked services report normal operation.`
          : `${degradedRows.length} of ${okRows.length} checked services report a problem${tail.length ? `; ${tail.join('; ')}` : ''}.`,
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

export default { tools, callTool, meter: { credits: 1 } } satisfies McpToolExport;
