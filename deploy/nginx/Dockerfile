FROM node:26-alpine@sha256:e88a35be04478413b7c71c455cd9865de9b9360e1f43456be5951032d7ac1a66 AS web-build

RUN corepack enable
WORKDIR /web
COPY web-starter-web/package.json web-starter-web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web-starter-web/ ./
RUN pnpm build

FROM nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236
RUN apk del \
        nginx-module-acme \
        nginx-module-geoip \
        nginx-module-image-filter \
        nginx-module-njs \
        nginx-module-xslt \
        nginx \
    && apk upgrade --no-cache \
    && apk add --no-cache nginx \
    && rm -f /etc/nginx/conf.d/default.conf \
    && mkdir -p /etc/nginx/private.d /etc/nginx/public.d /etc/nginx/shared /etc/nginx/snippets /etc/nginx/tls \
    && touch /etc/nginx/tls/fullchain.pem /etc/nginx/tls/privkey.pem \
    && chown -R 101:101 /etc/nginx/tls \
    && chmod 500 /etc/nginx/tls \
    && chmod 400 /etc/nginx/tls/fullchain.pem /etc/nginx/tls/privkey.pem
COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf
COPY deploy/nginx/nginx-public.conf /etc/nginx/nginx-public.conf
COPY deploy/nginx/forwarded-maps.conf /etc/nginx/shared/forwarded-maps.conf
COPY deploy/nginx/proxy-headers.conf /etc/nginx/snippets/web-starter-proxy-headers.conf
COPY deploy/nginx/default.conf /etc/nginx/private.d/default.conf
COPY deploy/nginx/external-mcp.conf /etc/nginx/public.d/default.conf
COPY --from=web-build /web/dist /usr/share/nginx/html

# The stock nginx user is uid/gid 101 in the Alpine image. Both listeners use
# unprivileged ports, and writable runtime state is redirected to /tmp by the
# checked-in nginx configs so the final container can run read-only.
USER 101:101
EXPOSE 8080 8443
