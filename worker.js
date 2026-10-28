
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type,Authorization",
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json; charset=utf-8",
    },
  });

const hex = (buffer) =>
  [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

const randomHex = (length) => {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return hex(bytes);
};

const sha256 = async (value) =>
  hex(
    await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value)
    )
  );

async function hashPassword(password, salt = randomHex(16)) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const saltBytes = Uint8Array.from(
    salt.match(/.{2}/g).map((x) => parseInt(x, 16))
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 120000,
      hash: "SHA-256",
    },
    key,
    256
  );

  return `pbkdf2$${salt}$${hex(bits)}`;
}

async function verifyPassword(password, stored) {
  const [algorithm, salt] = String(stored).split("$");

  if (algorithm !== "pbkdf2" || !salt) {
    return false;
  }

  return (await hashPassword(password, salt)) === stored;
}

async function createSession(db, userId) {
  const token = randomHex(32);
  const tokenHash = await sha256(token);
  const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;

  await db
    .prepare(
      "INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)"
    )
    .bind(tokenHash, userId, expires)
    .run();

  return token;
}

async function currentUser(request, db) {
  const authorization = request.headers.get("Authorization") || "";
  const token = authorization.startsWith("Bearer ")
    ? authorization.slice(7)
    : "";

  if (!token) return null;

  return (
    (await db
      .prepare(
        `SELECT u.id,u.username,u.display_name,u.bio,u.avatar_url,u.email
         FROM sessions s
         JOIN users u ON u.id=s.user_id
         WHERE s.token_hash=? AND s.expires_at>?`
      )
      .bind(await sha256(token), Date.now())
      .first()) || null
  );
}

async function needUser(request, env) {
  const user = await currentUser(request, env.DB);

  return user
    ? { user }
    : { response: json({ error: "Please log in again." }, 401) };
}

function postId(path) {
  const match = path.match(
    /^\/api\/posts\/(\d+)(?:\/(like|bookmark|comments))?$/
  );

  return match
    ? { id: Number(match[1]), action: match[2] || "" }
    : null;
}

async function postList(env, user) {
  const result = await env.DB
    .prepare(
      `SELECT
         p.id,p.user_id,p.caption,p.subject,p.post_type,p.tags,p.created_at,
         u.username,u.display_name,u.bio,u.avatar_url,
         (SELECT COUNT(*) FROM likes l
          WHERE l.post_id=p.id) AS likes_count,
         EXISTS(
           SELECT 1 FROM likes l
           WHERE l.post_id=p.id AND l.user_id=?
         ) AS liked,
         EXISTS(
           SELECT 1 FROM bookmarks b
           WHERE b.post_id=p.id AND b.user_id=?
         ) AS bookmarked
       FROM posts p
       JOIN users u ON u.id=p.user_id
       ORDER BY p.id DESC
       LIMIT 200`
    )
    .bind(user?.id || -1, user?.id || -1)
    .all();

  const posts = [];

  for (const p of result.results || []) {
    const comments = await env.DB
      .prepare(
        `SELECT c.id,c.user_id,c.content,c.created_at,u.username
         FROM comments c
         JOIN users u ON u.id=c.user_id
         WHERE c.post_id=?
         ORDER BY c.id ASC`
      )
      .bind(p.id)
      .all();

    const likes = await env.DB
      .prepare("SELECT user_id FROM likes WHERE post_id=?")
      .bind(p.id)
      .all();

    const bookmarks = await env.DB
      .prepare("SELECT user_id FROM bookmarks WHERE post_id=?")
      .bind(p.id)
      .all();

    posts.push({
      id: String(p.id),
      user_id: p.user_id,
      user: p.username,
      cap: p.caption || "",
      subj: p.subject || "Other",
      type: p.post_type || "Question",
      tags: (p.tags || "").split(",").filter(Boolean),
      imgs: [],
      t: Date.parse(p.created_at + "Z") || Date.now(),
      likes: (likes.results || []).map((item) => item.user_id),
      liked: Boolean(p.liked),
      saved: (bookmarks.results || []).map((item) => item.user_id),
      bookmarked: Boolean(p.bookmarked),
      comments: (comments.results || []).map((c) => ({
        id: c.id,
        user_id: c.user_id,
        user: c.username,
        text: c.content,
        t: Date.parse(c.created_at + "Z") || Date.now(),
      })),
      profile: {
        id: p.user_id,
        username: p.username,
        display: p.display_name || p.username,
        bio: p.bio || "",
        pic: p.avatar_url || "",
        col: "#5b3df5",
        follow: [],
      },
    });
  }

  return posts;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    try {
      if (path === "/api/health") {
        await env.DB.prepare("SELECT 1").first();

        return json({
          status: "ok",
          database: "connected",
        });
      }

      if (path === "/api/register" && method === "POST") {
        const body = await request.json();

        const username = String(body.username || "")
          .trim()
          .toLowerCase();

        const email = String(body.email || "")
          .trim()
          .toLowerCase();

        const password = String(body.password || "");

        const display = String(
          body.display_name || username
        )
          .trim()
          .slice(0, 40);

        if (!/^[a-z0-9_]{3,20}$/.test(username)) {
          return json(
            {
              error:
                "Username must be 3–20 characters: letters, numbers or underscores.",
            },
            400
          );
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
          return json(
            { error: "Enter a valid email address." },
            400
          );
        }

        if (password.length < 8 || password.length > 128) {
          return json(
            { error: "Password must be at least 8 characters." },
            400
          );
        }

        const existing = await env.DB
          .prepare(
            "SELECT id FROM users WHERE username=? OR email=?"
          )
          .bind(username, email)
          .first();

        if (existing) {
          return json(
            {
              error:
                "That username or email is already registered.",
            },
            409
          );
        }

        const passwordHash = await hashPassword(password);

        const result = await env.DB
          .prepare(
            `INSERT INTO users
             (username,display_name,password_hash,email)
             VALUES(?,?,?,?)`
          )
          .bind(
            username,
            display || username,
            passwordHash,
            email
          )
          .run();

        const user = {
          id: result.meta.last_row_id,
          username,
          display_name: display || username,
          email,
          bio: "",
          avatar_url: "",
        };

        const token = await createSession(
          env.DB,
          user.id
        );

        return json({ token, user }, 201);
      }

      if (path === "/api/login" && method === "POST") {
        const body = await request.json();

        const login = String(body.login || "")
          .trim()
          .toLowerCase();

        const password = String(body.password || "");

        const row = await env.DB
          .prepare(
            "SELECT * FROM users WHERE username=? OR email=?"
          )
          .bind(login, login)
          .first();

        if (
          !row ||
          !(await verifyPassword(password, row.password_hash))
        ) {
          return json(
            {
              error: "Incorrect username/email or password.",
            },
            401
          );
        }

        const user = {
          id: row.id,
          username: row.username,
          display_name: row.display_name,
          email: row.email || "",
          bio: row.bio || "",
          avatar_url: row.avatar_url || "",
        };

        const token = await createSession(env.DB, row.id);

        return json({ token, user });
      }

      if (path === "/api/me" && method === "GET") {
        const user = await currentUser(request, env.DB);

        return user
          ? json({ user })
          : json({ error: "Please log in again." }, 401);
      }

      if (path === "/api/logout" && method === "POST") {
        const authorization =
          request.headers.get("Authorization") || "";

        const token = authorization.startsWith("Bearer ")
          ? authorization.slice(7)
          : "";

        if (token) {
          await env.DB
            .prepare(
              "DELETE FROM sessions WHERE token_hash=?"
            )
            .bind(await sha256(token))
            .run();
        }

        return json({ ok: true });
      }

      if (path === "/api/posts" && method === "GET") {
        const user = await currentUser(request, env.DB);

        return json({
          posts: await postList(env, user),
        });
      }

      if (path === "/api/posts" && method === "POST") {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const body = await request.json();

        const caption = String(body.caption || "").trim();

        const subject = String(
          body.subject || "Other"
        ).slice(0, 40);

        const type = String(
          body.post_type || "Question"
        ).slice(0, 40);

        const tags = [
          ...new Set(
            String(body.tags || "")
              .split(/[\s,#]+/)
              .filter(Boolean)
              .map((tag) => tag.toLowerCase().slice(0, 24))
          ),
        ]
          .slice(0, 8)
          .join(",");

        if (!caption || caption.length > 500) {
          return json(
            {
              error: "Write a post (up to 500 characters).",
            },
            400
          );
        }

        const result = await env.DB
          .prepare(
            `INSERT INTO posts
             (user_id,caption,subject,post_type,tags)
             VALUES(?,?,?,?,?)`
          )
          .bind(
            user.id,
            caption,
            subject,
            type,
            tags
          )
          .run();

        return json(
          { ok: true, id: result.meta.last_row_id },
          201
        );
      }

      const match = postId(path);

      if (
        match &&
        match.action === "" &&
        method === "DELETE"
      ) {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const post = await env.DB
          .prepare("SELECT user_id FROM posts WHERE id=?")
          .bind(match.id)
          .first();

        if (!post) {
          return json({ error: "Post not found." }, 404);
        }

        if (post.user_id !== user.id) {
          return json(
            { error: "You can only delete your own posts." },
            403
          );
        }

        await env.DB
          .prepare("DELETE FROM posts WHERE id=?")
          .bind(match.id)
          .run();

        return json({ ok: true });
      }

      if (
        match &&
        ["like", "bookmark"].includes(match.action) &&
        method === "POST"
      ) {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const post = await env.DB
          .prepare("SELECT id FROM posts WHERE id=?")
          .bind(match.id)
          .first();

        if (!post) {
          return json({ error: "Post not found." }, 404);
        }

        const table =
          match.action === "like" ? "likes" : "bookmarks";

        const exists = await env.DB
          .prepare(
            `SELECT 1 FROM ${table}
             WHERE user_id=? AND post_id=?`
          )
          .bind(user.id, match.id)
          .first();

        if (exists) {
          await env.DB
            .prepare(
              `DELETE FROM ${table}
               WHERE user_id=? AND post_id=?`
            )
            .bind(user.id, match.id)
            .run();
        } else {
          await env.DB
            .prepare(
              `INSERT INTO ${table}(user_id,post_id)
               VALUES(?,?)`
            )
            .bind(user.id, match.id)
            .run();
        }

        return json({
          ok: true,
          active: !exists,
        });
      }

      if (
        match &&
        match.action === "comments" &&
        method === "POST"
      ) {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const body = await request.json();
        const content = String(body.content || "").trim();

        if (!content || content.length > 300) {
          return json(
            {
              error: "Comment must be 1–300 characters.",
            },
            400
          );
        }

        const post = await env.DB
          .prepare("SELECT id FROM posts WHERE id=?")
          .bind(match.id)
          .first();

        if (!post) {
          return json({ error: "Post not found." }, 404);
        }

        const result = await env.DB
          .prepare(
            `INSERT INTO comments(post_id,user_id,content)
             VALUES(?,?,?)`
          )
          .bind(match.id, user.id, content)
          .run();

        return json({
          ok: true,
          id: result.meta.last_row_id,
        });
      }

      const commentMatch = path.match(
        /^\/api\/comments\/(\d+)$/
      );

      if (commentMatch && method === "DELETE") {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const commentId = Number(commentMatch[1]);

        const comment = await env.DB
          .prepare("SELECT user_id FROM comments WHERE id=?")
          .bind(commentId)
          .first();

        if (!comment) {
          return json(
            { error: "Comment not found." },
            404
          );
        }

        if (comment.user_id !== user.id) {
          return json(
            {
              error: "You can only delete your own comments.",
            },
            403
          );
        }

        await env.DB
          .prepare("DELETE FROM comments WHERE id=?")
          .bind(commentId)
          .run();

        return json({ ok: true });
      }

      const followMatch = path.match(
        /^\/api\/users\/(\d+)\/follow$/
      );

      if (followMatch && method === "POST") {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const target = Number(followMatch[1]);

        if (target === user.id) {
          return json(
            { error: "You cannot follow yourself." },
            400
          );
        }

        const targetUser = await env.DB
          .prepare("SELECT id FROM users WHERE id=?")
          .bind(target)
          .first();

        if (!targetUser) {
          return json(
            { error: "User not found." },
            404
          );
        }

        const exists = await env.DB
          .prepare(
            `SELECT 1 FROM follows
             WHERE follower_id=? AND following_id=?`
          )
          .bind(user.id, target)
          .first();

        if (exists) {
          await env.DB
            .prepare(
              `DELETE FROM follows
               WHERE follower_id=? AND following_id=?`
            )
            .bind(user.id, target)
            .run();
        } else {
          await env.DB
            .prepare(
              `INSERT INTO follows(follower_id,following_id)
               VALUES(?,?)`
            )
            .bind(user.id, target)
            .run();
        }

        return json({
          ok: true,
          active: !exists,
        });
      }

      if (path === "/api/users" && method === "GET") {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const result = await env.DB
          .prepare(
            `SELECT
               u.id,u.username,u.display_name,u.bio,u.avatar_url,
               EXISTS(
                 SELECT 1 FROM follows f
                 WHERE f.follower_id=? AND f.following_id=u.id
               ) AS following,
               (SELECT COUNT(*) FROM follows f
                WHERE f.following_id=u.id) AS followers,
               (SELECT COUNT(*) FROM follows f
                WHERE f.follower_id=u.id) AS following_count
             FROM users u
             ORDER BY u.username`
          )
          .bind(user.id)
          .all();

        return json({
          users: result.results || [],
        });
      }

      if (path === "/api/account" && method === "DELETE") {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        await env.DB
          .prepare("DELETE FROM users WHERE id=?")
          .bind(user.id)
          .run();

        return json({ ok: true });
      }

      if (path === "/api/profile" && method === "POST") {
        const { user, response } = await needUser(
          request,
          env
        );

        if (response) return response;

        const body = await request.json();

        const display = String(
          body.display_name || user.username
        )
          .trim()
          .slice(0, 40);

        const bio = String(body.bio || "")
          .trim()
          .slice(0, 150);

        await env.DB
          .prepare(
            "UPDATE users SET display_name=?,bio=? WHERE id=?"
          )
          .bind(display, bio, user.id)
          .run();

        return json({ ok: true });
      }

      return json(
        { error: "API route not found." },
        404
      );
    } catch (error) {
      return json(
        {
          error:
            "Server error. Check that the D1 schema is up to date.",
          detail: String(error?.message || error),
        },
        500
      );
    }
  },
};
