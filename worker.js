
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();

        return Response.json({
          status: "ok",
          database: "connected"
        });
      } catch (error) {
        return Response.json({
          status: "error",
          message: "Database connection failed"
        }, { status: 500 });
      }
    }

    return env.ASSETS.fetch(request);
  }
};
