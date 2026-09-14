# Setup Guide

> **This file is read by the automated evaluation pipeline. Be precise and complete.**

## Prerequisites

Choose one supported setup:

- [ ] Docker Desktop 24+ for the production container
- [ ] Node.js 20+ and npm 10+ for local development

## Environment Variables

No environment variables are required. The current prototype uses local mock data.

## Docker Setup

```bash
# Clone the repository
git clone https://github.com/Ankitlakhatariya/bob-ai-hackathon-threat-intelligence.git
cd bob-ai-hackathon-threat-intelligence

# Build the production image
docker build -t threatlens .

# Start the container
docker run --rm --name threatlens -p 8080:80 threatlens
```

Open `http://localhost:8080` in a browser. Stop the container with `Ctrl+C`.

## Local Development

```bash
cd src/frontend
npm install
npm run dev
```

## Running the Application

```bash
npm run dev
```

The development application will be available at: `http://localhost:5173`.

## Validation

```bash
cd src/frontend
npm run build
```

## Troubleshooting

| Issue | Solution |
|---|---|
| Docker command is not recognized | Install Docker Desktop and restart the terminal. |
| Port 8080 is already in use | Map another host port, for example `-p 8081:80`. |
| A client-side route returns 404 | Use the repository Docker image; Nginx is configured with SPA fallback. |
