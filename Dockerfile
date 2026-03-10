# Start from a Node.js 18 Debian slim image
FROM node:18-bookworm-slim

# Set the working directory
WORKDIR /app

# Install required system packages
# - iputils: for ping
# - traceroute: for traceroute
# - bind-tools: for nslookup/dig
# - mtr: for mtr
# - openssl: for openssl s_connect
# - curl: for curl HTTP timing stats
RUN apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates \
		iputils-ping \
		traceroute \
		dnsutils \
		mtr \
		openssl \
		curl \
	&& rm -rf /var/lib/apt/lists/*

# Copy package manifests
COPY package.json package-lock.json ./

# Install Node.js dependencies
RUN npm ci

# Create data directory for persistent SQLite database
RUN mkdir -p /app/data && chown -R node:node /app/data

# Copy the rest of the application source code
COPY . .

# Build local Tailwind CSS for production
RUN npm run build:tailwind

# Remove dev dependencies from runtime image
RUN npm prune --omit=dev

# Expose the port the app runs on
#EXPOSE 8080

# Define the command to run the application
CMD [ "node", "server.js" ]

