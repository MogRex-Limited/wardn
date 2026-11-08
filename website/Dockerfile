# The wardn documentation site, for internal hosting.
#   docker build -t wardn-docs website/
#   docker run -p 8080:8080 wardn-docs
# Images are pinned by digest; refresh them deliberately.

FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8 AS build
WORKDIR /site
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.29-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /site/dist /usr/share/nginx/html
EXPOSE 8080
