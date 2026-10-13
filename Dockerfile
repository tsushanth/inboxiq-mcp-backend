FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev
ENV NODE_ENV=production
COPY . .
CMD ["node", "server.js"]
