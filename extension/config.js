// src/config.js

// Toggle this for local vs production testing
const USE_LOCAL_BACK = false;
const USE_LOCAL_FRONT = true;

const config = {
    // API URLs
    apiUrl: USE_LOCAL_BACK 
        ? 'http://localhost:5000'
        : 'https://prodpush--scanaraai.us-east4.hosted.app/',
    
    // Web dashboard URL
    webUrl: USE_LOCAL_FRONT
        ? 'http://localhost:5173'
        : 'https://your-web-app-url.com',
    
    // Firebase API Key (can be overridden in VS Code settings)
    defaultFirebaseApiKey: 'AIzaSyB4z0HPzkI5YPsCVjWIQNyFbXsRc2MBkF0'
};

module.exports = config;