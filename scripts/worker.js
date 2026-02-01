export default {
    async fetch(request) {
        const owner = "sauzerOS";
        const repo = "hokuto";
        const url = new URL(request.url);

        // Helper to fetch latest release data
        const getLatestRelease = async () => {
            const apiUrl = `https://api.github.com/repos/${owner}/${repo}/releases/latest`;
            const resp = await fetch(apiUrl, {
                headers: { "User-Agent": "cloudflare-worker" }
            });
            if (!resp.ok) return null;
            return await resp.json();
        };

        // 1. /install -> Redirect to 'hokutostrap' script in latest release
        if (url.pathname === "/install") {
            const release = await getLatestRelease();
            if (!release) return new Response("GitHub API Error", { status: 500 });

            const asset = release.assets.find(a => a.name === "hokutostrap");
            if (!asset) {
                return new Response("Installer script 'hokutostrap' not found in latest release", { status: 404 });
            }

            return Response.redirect(asset.browser_download_url, 302);
        }

        // 2. /hokuto.tar.xz AND /hokuto.tar.xz.sig -> Redirect to arch-specific assets
        if (url.pathname === "/hokuto.tar.xz" || url.pathname === "/hokuto.tar.xz.sig") {
            const arch = url.searchParams.get("arch") || "amd64"; // Default to amd64
            const isSig = url.pathname.endsWith(".sig");

            const release = await getLatestRelease();
            if (!release) return new Response("GitHub API Error", { status: 500 });

            // Find asset matching architecture and file type
            // Pattern assumption:
            // Binary: hokuto-vX.Y.Z-<arch>.tar.xz   (contains 'arch' AND ends with .tar.xz)
            // Sig:    hokuto-vX.Y.Z-<arch>.tar.xz.sig (contains 'arch' AND ends with .sig)
            const asset = release.assets.find(a => {
                // Must contain the requested architecture
                if (!a.name.includes(arch)) return false;

                if (isSig) {
                    return a.name.endsWith(".sig");
                } else {
                    return a.name.endsWith(".tar.xz");
                }
            });

            if (!asset) {
                return new Response(`Asset not found for arch=${arch} (sig=${isSig})`, { status: 404 });
            }

            return Response.redirect(asset.browser_download_url, 302);
        }

        // Default: Redirect root to /install for convenience
        return Response.redirect(`${url.origin}/install`, 302);
    }
}
