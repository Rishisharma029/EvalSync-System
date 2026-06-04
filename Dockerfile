# Base Node image
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Copy dependency definitions
COPY package.json package-lock.json ./

# Install production dependencies cleanly using npm ci
RUN npm ci --omit=dev

# Copy application files and change ownership to node user
COPY --chown=node:node . .

# Use non-root node user for container execution
USER node

# Expose port
EXPOSE 3000

# Set production environment
ENV NODE_ENV=production

# Start command
CMD ["node", "server.js"]
