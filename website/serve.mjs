// Serves the built documentation site (website/dist/) for hosts that run a
// process instead of a container. It uses only Node's standard library, so
// it runs on any Node.js 18 or newer, and sends the same security headers as
// nginx.conf. The site has no server-side code: this only serves files.
//
//   node website/serve.mjs          # PORT (default 3002), HOST (default 0.0.0.0)
import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { stat } from "node:fs/promises";
import { extname, join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("./dist/", import.meta.url));
const port = Number(process.env.PORT) || 3002;
const host = process.env.HOST || "0.0.0.0";

const types = {
	".html": "text/html; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".mjs": "text/javascript; charset=utf-8",
	".json": "application/json; charset=utf-8",
	".xml": "application/xml; charset=utf-8",
	".txt": "text/plain; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".webp": "image/webp",
	".ico": "image/x-icon",
	".woff": "font/woff",
	".woff2": "font/woff2",
	".wasm": "application/wasm",
	".pf_meta": "application/octet-stream",
	".pf_fragment": "application/octet-stream",
	".pf_index": "application/octet-stream",
};
const longCache = new Set([".css", ".js", ".svg", ".woff", ".woff2", ".png", ".webp"]);

const security = {
	"X-Content-Type-Options": "nosniff",
	"X-Frame-Options": "DENY",
	"Referrer-Policy": "no-referrer",
	"Content-Security-Policy":
		"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; frame-ancestors 'none'",
};

// file returns the path of a regular file inside root, or null.
async function file(path) {
	const full = normalize(join(root, path));
	if (full !== root.slice(0, -1) && !full.startsWith(root)) return null; // outside dist/
	try {
		return (await stat(full)).isFile() ? full : null;
	} catch {
		return null;
	}
}

// resolve mirrors nginx's try_files $uri $uri/ $uri.html.
async function resolve(pathname) {
	return (await file(pathname)) ?? (await file(join(pathname, "index.html"))) ?? (await file(`${pathname}.html`));
}

function send(res, status, path, method) {
	const ext = extname(path);
	res.writeHead(status, {
		...security,
		"Content-Type": types[ext] ?? "application/octet-stream",
		"Cache-Control": status === 200 && longCache.has(ext) ? "public, max-age=604800, immutable" : "no-cache",
	});
	if (method === "HEAD") return res.end();
	createReadStream(path).on("error", () => res.destroy()).pipe(res);
}

createServer(async (req, res) => {
	if (req.method !== "GET" && req.method !== "HEAD") {
		res.writeHead(405, { ...security, Allow: "GET, HEAD" }).end();
		return;
	}
	let pathname;
	try {
		pathname = decodeURIComponent(new URL(req.url ?? "/", "http://localhost").pathname);
	} catch {
		res.writeHead(400, security).end();
		return;
	}
	if (pathname.includes("\0") || pathname.split(/[\\/]/).includes("..")) {
		res.writeHead(400, security).end();
		return;
	}
	const found = await resolve(pathname);
	if (found) return send(res, 200, found, req.method);
	const notFound = await file("404.html");
	if (notFound) return send(res, 404, notFound, req.method);
	res.writeHead(404, security).end();
}).listen(port, host, () => {
	console.log(`wardn docs on http://${host}:${port} (serving ${root.split(sep).join("/")})`);
});
