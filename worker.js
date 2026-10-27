
const json = (data, status = 200) =>
  Response.json(data, { status });

const encoder = new TextEncoder();

function hex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return hex(bytes);
}

async function sha256(value) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(value)
  );
  return hex(new Uint8Array(result));
}

async function hashPassword(password, salt = randomHex(16)) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: encoder.encode(salt),
      iterations: 120000
    },
    key,
    256
  );

  return `pbkdf2$${salt}$${hex(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "pbkdf2") {
    return false;
  }

  return (await hashPassword(password, parts[1])) === stored;
}

async function createSession(env, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000;

  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)"
  ).bind(tokenHash, userId, expiresAt).run();

  return token;
}

async function currentUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;

  const tokenHash = await sha256(auth.slice(7));

  const row = await env.DB.prepare(`
    SELECT users.id, users.username, users.display_name,
           users.email, users.bio, users.avatar_url
    FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).bind(tokenHash, Date.now()).first();

  return row || null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();
        return json({ status: "ok", database: "connected" });
      } catch {
        return json(
          { status: "error", message: "Database connection failed" },
          500
        );
      }
    }

    if (!path.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    if (request.method !== "POST" &&
        path !== "/api/me") {
      return json({ error: "Method not allowed" }, 405);
    }

    try {
      if (path === "/api/register" && request.method === "POST") {
        const body = await request.json();
        const username = String(body.username || "").trim().toLowerCase();
        const displayName = String(body.display_name || username).trim();
        const email = String(body.email || "").trim().toLowerCase();
        const password = String(body.password || "");

        if (!/^[a-z0-9_]{3,20}$/.test(username)) {
          return json({
            error: "Username must be 3–20 characters using letters, numbers, or underscores."
          }, 400);
        }

        if (!email || email.length > 254 || !email.includes("@")) {
          return json({ error: "Enter a valid email address." }, 400);
        }

        if (password.length < 8 || password.length > 128) {
          return json({ error: "Password must be 8–128 characters." }, 400);
        }

        const existing = await env.DB.prepare(
          "SELECT id FROM users WHERE username = ? OR email = ?"
        ).bind(username, email).first();

        if (existing) {
          return json({ error: "That username or email is already registered." }, 409);
        }

        const passwordHash = await hashPassword(password);

        const result = await env.DB.prepare(`
          INSERT INTO users (username, display_name, email, password_hash)
          VALUES (?, ?, ?, ?)
        `).bind(username, displayName || username, email, passwordHash).run();

        const userId = result.meta.last_row_id;
        const token = await createSession(env, userId);

        return json({
          token,
          user: {
            id: userId,
            username,
            display_name: displayName || username,
            email,
            bio: "",
            avatar_url: ""
          }
        }, 201);
      }

      if (path === "/api/login" && request.method === "POST") {
        const body = await request.json();
        const login = String(body.login || "").trim().toLowerCase();
        const password = String(body.password || "");

        const user = await env.DB.prepare(`
          SELECT id, username, display_name, email, bio,
                 avatar_url, password_hash
          FROM users
          WHERE username = ? OR email = ?
        `).bind(login, login).first();

        if (!user || !(await verifyPassword(password, user.password_hash))) {
          return json({ error: "Incorrect login details." }, 401);
        }

        const token = await createSession(env, user.id);
        const { password_hash, ...safeUser } = user;

        return json({ token, user: safeUser });
      }

      if (path === "/api/me" && request.method === "GET") {
        const user = await currentUser(request, env);
        if (!user) return json({ error: "Please log in again." }, 401);
        return json({ user });
      }

      if (path === "/api/logout" && request.method === "POST") {
        const auth = request.headers.get("Authorization") || "";

        if (auth.startsWith("Bearer ")) {
          const tokenHash = await sha256(auth.slice(7));
          await env.DB.prepare(
            "DELETE FROM sessions WHERE token_hash = ?"
          ).bind(tokenHash).run();
        }

        return json({ success: true });
      }

      return json({ error: "API route not found." }, 404);
    } catch (error) {
      console.error("API error:", error);
      return json({ error: "Something went wrong. Please try again." }, 500);
    }
  }
};
