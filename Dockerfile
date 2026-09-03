# WARDEN — stdio MCP server for Glama / Claude Desktop / Cursor
#
# Local:  docker build -t warden-mcp . && docker run --rm -i warden-mcp
# Glama:  does not use this file as-is — paste the Build steps / CMD from
#         docs/GLAMA.md into the admin form after submitting the GitHub repo.
FROM node:22-slim
WORKDIR /app

LABEL org.opencontainers.image.title="warden"
LABEL org.opencontainers.image.description="WARDEN MCP security firewall (stdio) — vet tool defs before they reach the model"
LABEL org.opencontainers.image.source="https://github.com/alexar76/warden"
LABEL org.opencontainers.image.licenses="MIT"
LABEL ai-market.mcp="true"

COPY package.json package-lock.json tsconfig.json ./
COPY src ./src
COPY README.md LICENSE ./

RUN npm ci \
 && npm run build \
 && npm prune --omit=dev

ENV NODE_ENV=production
# stdout = MCP wire; no secrets, no required env.
ENTRYPOINT ["node", "dist/mcp-server.js"]
