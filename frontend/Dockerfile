FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apk add --no-cache git

# Copy package files
COPY package*.json ./

# Clear npm cache and install dependencies
RUN npm cache clean --force && \
    npm install --legacy-peer-deps

# Copy application code
COPY . .

# Set environment variables
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=development

# Expose port
EXPOSE 3000

# Start the application in development mode
CMD ["npm", "run", "dev"] 