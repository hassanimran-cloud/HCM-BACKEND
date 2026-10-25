# HCM Lite Backend (Vercel / Express / MongoDB)

## Required environment variables in Vercel
- `MONGODB_URI`: MongoDB Atlas connection string
- `JWT_SECRET`: long random secret (at least 32 characters)
- `CLIENT_ORIGIN`: exact deployed frontend origin, e.g. `https://hcm-lite-frontend.vercel.app`
- Optional: `ADMIN_EMAIL`, `ADMIN_PASSWORD` to create the initial Admin on first DB connection; otherwise use the app's setup screen.
- Optional: `GEMINI_API_KEY`, `GEMINI_MODEL`

Do not commit `.env` or real secrets to GitHub.

## Deploy
1. Push this folder/repository to GitHub.
2. Import the backend repo into Vercel.
3. Add the environment variables above in Project Settings → Environment Variables.
4. Deploy. The API routes are served by the Express function.

## Local
1. `npm install`
2. Copy `.env.example` to `.env` and fill real values.
3. `npm run dev`
The API listens on port 5000.

Set `CLIENT_ORIGIN` to the deployed frontend URL. For local development, set it to `http://localhost:5173`.
