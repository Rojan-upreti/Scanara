<img width="2934" height="1596" alt="image" src="https://github.com/user-attachments/assets/58d08d36-4bdf-4e0f-9aef-34c831ed1aa8" />

# Firebase Authentication Backend & Frontend

A complete authentication system with Node.js/Express backend and React frontend using Firebase Authentication.

## Architecture

- **Backend**: Node.js + Express with Firebase Admin SDK for token verification
- **Frontend**: React (Vite) with Firebase Client SDK
- **Authentication Flow**: Login → Backend verifies token → Redirect to Dashboard
- **Pages**: Index (landing/login) → Dashboard (after authentication)

## Setup Instructions

### Backend Setup

1. Navigate to the backend directory:
```bash
cd backend
```

2. Install dependencies:
```bash
npm install
```

3. The `.env` file has been created with Firebase Admin SDK credentials. Make sure it's properly configured.

4. Start the backend server:
```bash
npm start
```

The server will run on `http://localhost:5000`

### Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Create a `.env` file in the frontend directory with the following content:
```
VITE_FIREBASE_API_KEY=AIzaSyB4z0HPzkI5YPsCVjWIQNyFbXsRc2MBkF0
VITE_FIREBASE_AUTH_DOMAIN=scanaraai.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=scanaraai
VITE_FIREBASE_STORAGE_BUCKET=scanaraai.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=840074904641
VITE_FIREBASE_APP_ID=1:840074904641:web:7f10e0ee9eec577de972c0
VITE_FIREBASE_MEASUREMENT_ID=G-QVCDEXRW34
VITE_BACKEND_URL=http://localhost:5000
```

3. Install dependencies:
```bash
npm install
```

4. Start the development server:
```bash
npm run dev
```

The frontend will run on `http://localhost:5173`

## Authentication Flow

1. User visits the landing page (Index) at `/`
2. User logs in with email/password or Google sign-in
3. Frontend gets Firebase ID token after successful authentication
4. Frontend sends token to backend `/api/auth/verify` endpoint
5. Backend verifies token using Firebase Admin SDK
6. On successful verification, user is redirected to Dashboard at `/dashboard`
7. Dashboard is protected and requires authentication

## Features

- Email/Password authentication
- Google Sign-In authentication
- Backend token verification
- Protected routes
- Session management with localStorage
- Responsive UI

## API Endpoints

### POST `/api/auth/verify`
Verifies Firebase ID token from frontend
- Headers: `Authorization: Bearer <token>`
- Returns: User information if token is valid

### GET `/api/auth/check`
Checks if user is authenticated
- Headers: `Authorization: Bearer <token>`
- Returns: Authentication status and user information

## Security Notes

- Service account credentials are stored in `.env` file (not committed to git)
- All sensitive data uses environment variables
- CORS is configured for frontend communication
- Token verification happens on backend for all protected routes

## Project Structure

```
backend/
  ├── config/
  │   └── firebase-admin.js
  ├── middleware/
  │   └── auth.js
  ├── routes/
  │   └── auth.js
  ├── .env
  ├── .gitignore
  ├── package.json
  └── server.js

frontend/
  ├── src/
  │   ├── config/
  │   │   └── firebase.js
  │   ├── services/
  │   │   └── auth.js
  │   ├── pages/
  │   │   ├── Index.jsx
  │   │   └── Dashboard.jsx
  │   ├── components/
  │   │   └── ProtectedRoute.jsx
  │   ├── App.jsx
  │   └── main.jsx
  ├── .env
  ├── .gitignore
  ├── package.json
  └── vite.config.js
```


