FROM node:24-alpine AS build

WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web/ ./
RUN npm run build

FROM node:24-alpine

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000

WORKDIR /app
COPY --from=build /app/build ./build

USER node
EXPOSE 3000
CMD ["node", "build"]
