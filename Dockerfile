# Start from a Node.js 18 Alpine image
FROM node:18-alpine

# Set the working directory
WORKDIR /app

# Install required system packages
# - iputils: for ping
# - traceroute: for traceroute
# - bind-tools: for nslookup/dig
# - mtr: for mtr
# - openssl: for openssl s_connect
# - curl: for curl HTTP timing stats
RUN apk add --no-cache iputils traceroute bind-tools mtr openssl curl

# Copy package.json and package-lock.json
COPY package.json ./

# Install Node.js dependencies
RUN npm install

# Copy the rest of the application source code
COPY . .

# Expose the port the app runs on
EXPOSE 8080

# Define the command to run the application
CMD [ "node", "server.js" ]

