// hokuto.xdd.ovh: redirects to the assets of the latest hokuto release.
//
//   /install, /hokutostrap         -> hokutostrap
//   /hokuto-builder                -> hokuto-builder
//     wget names a download after the requested URL, not the redirect or the
//     Content-Disposition filename, so `wget hokuto.xdd.ovh` saves index.html
//     while `wget hokuto.xdd.ovh/hokutostrap` saves hokutostrap.
//   /hokuto.tar.xz?arch=<arch>     -> hokuto-<version>-<arch>.tar.xz
//   /hokuto.tar.xz.sig?arch=<arch> -> its signature
//
// Finding the latest release takes a GitHub API call. Unauthenticated, GitHub
// allows 60 of those per hour per IP, and a Worker's requests leave from
// shared Cloudflare addresses, so calling it on every request fails in bursts.
// The answer is therefore cached for RELEASE_TTL seconds, the last good one is
// kept (STALE_TTL) and served when GitHub refuses, and a GITHUB_TOKEN secret,
// if configured, raises the limit to 5000 per hour.

const OWNER = "sauzerOS";
const REPO = "hokuto";
const RELEASE_TTL = 600; // fresh: reuse without asking GitHub
const STALE_TTL = 7 * 24 * 3600; // fallback when GitHub refuses
const API_URL = `https://api.github.com/repos/${OWNER}/${REPO}/releases/latest`;
const CACHE_KEY = "https://hokuto-release-cache.internal/latest";

async function fetchRelease(env) {
    const headers = {
        "User-Agent": "hokuto-release-worker",
        Accept: "application/vnd.github+json",
    };
    if (env && env.GITHUB_TOKEN) {
        headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
    }
    let lastError = "unknown error";
    for (let attempt = 0; attempt < 2; attempt++) {
        try {
            const resp = await fetch(API_URL, { headers });
            if (resp.ok) {
                const release = await resp.json();
                if (release && Array.isArray(release.assets)) {
                    return { release };
                }
                lastError = "GitHub API returned no asset list";
            } else {
                lastError = `GitHub API answered ${resp.status}`;
            }
        } catch (err) {
            lastError = `GitHub API request failed: ${err}`;
        }
    }
    return { error: lastError };
}

// Latest release, from the cache when fresh; on GitHub errors the last good
// answer is used even if it is older than RELEASE_TTL.
async function getLatestRelease(env, ctx) {
    const cache = caches.default;
    const cached = await cache.match(CACHE_KEY);
    let stale = null;
    if (cached) {
        const entry = await cached.json();
        if (Date.now() - entry.storedAt < RELEASE_TTL * 1000) {
            return entry.release;
        }
        stale = entry.release;
    }

    const { release, error } = await fetchRelease(env);
    if (release) {
        const slim = {
            tag_name: release.tag_name,
            assets: release.assets.map((a) => ({ name: a.name, browser_download_url: a.browser_download_url })),
        };
        const body = JSON.stringify({ storedAt: Date.now(), release: slim });
        const put = cache.put(CACHE_KEY, new Response(body, {
            headers: { "Content-Type": "application/json", "Cache-Control": `max-age=${STALE_TTL}` },
        }));
        if (ctx) ctx.waitUntil(put); else await put;
        return slim;
    }
    if (stale) {
        return stale;
    }
    throw new Error(error);
}

// Scripts shipped as release assets under their own names.
const SCRIPTS = {
    "/install": "hokutostrap",
    "/hokutostrap": "hokutostrap",
    "/hokuto-builder": "hokuto-builder",
};

function findAsset(release, pathname, arch) {
    if (SCRIPTS[pathname]) {
        return release.assets.find((a) => a.name === SCRIPTS[pathname]);
    }
    const isSig = pathname.endsWith(".sig");
    return release.assets.find((a) => a.name.includes(arch) && a.name.endsWith(isSig ? ".tar.xz.sig" : ".tar.xz"));
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const known = url.pathname in SCRIPTS || url.pathname === "/hokuto.tar.xz" || url.pathname === "/hokuto.tar.xz.sig";
        if (!known) {
            return Response.redirect(`${url.origin}/install`, 302);
        }
        const arch = url.searchParams.get("arch") || "amd64";
        try {
            const release = await getLatestRelease(env, ctx);
            const asset = findAsset(release, url.pathname, arch);
            if (!asset) {
                const what = SCRIPTS[url.pathname] || `${url.pathname.slice(1)} for arch=${arch}`;
                return new Response(`No ${what} in release ${release.tag_name}\n`, { status: 404 });
            }
            return Response.redirect(asset.browser_download_url, 302);
        } catch (err) {
            // A readable answer instead of Cloudflare's opaque "error code: 1101".
            return new Response(`Could not look up the latest hokuto release: ${err.message}\n`, {
                status: 503,
                headers: { "Retry-After": "30" },
            });
        }
    },
};
