FROM node:24-alpine AS web-build

RUN corepack enable
WORKDIR /web
COPY web-starter-web/package.json web-starter-web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web-starter-web/ ./
RUN pnpm build

FROM nginx:1.28-alpine
COPY deploy/nginx/forwarded-maps.conf /etc/nginx/conf.d/00-web-starter-forwarded-maps.conf
COPY deploy/nginx/proxy-headers.conf /etc/nginx/snippets/web-starter-proxy-headers.conf
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=web-build /web/dist /usr/share/nginx/html
EXPOSE 8080 443
