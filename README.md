# BLACKSAUCE

A Node.js-based secure code testing platform with user authentication, admin panel, and code execution capabilities.

## Features

- User registration and login
- Admin panel for managing users
- Terminal for code execution (JavaScript)
- Activity logging
- Session-based authentication

## Quick Start (Local)

```bash
npm install
npm start
```

Open http://localhost:8080

## Dependencies

- Node.js
- Express.js
- Express-session
- EJS (for templating)
- Crypto, fs, path, child_process (built-in)

**Default Admin:**
- Username: `admin`
- Password: `admin123`

## Deploy to Vercel

```bash
npm i -g vercel
vercel
```

Or push to GitHub and import at vercel.com.

**Note:** Code execution is disabled on Vercel. Use local server for that feature.

## Project Structure

```
.
├── main.go           # Local server (full features)
├── api/index.go      # Vercel handler (limited)
├── vercel.json       # Vercel config
├── go.mod
└── templates/        # HTML templates (local only)
```

## Tech Stack

- Go 1.22
- Vercel (deployment)