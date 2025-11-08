import admin from 'firebase-admin';
import dotenv from 'dotenv';

dotenv.config();

// Initialize Firebase Admin SDK with service account
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID || "scanaraai",
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID || "b1be6fb361894ae7aadf60948e4f88abef21ef21",
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n') || "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDW+1s0/iF89j1g\nsozJLU8IcMjD0yBmhNaR+lPCqmDMpSh0sNSYDjjt6OILMrOJQ3i0YrtcnFQfkft1\nZv7XwWg+N9HfFeP41wps+D2jvNgvTXjb5juml0O1WFR1h5xEVFrwLhV0Qz83m2zp\nQC0+HNHhN8oxWXksO2fsCSB0mxHIOEWjbS8XJ/03uaCEK+H+/Epn5P7GKeVgBhd8\nIy5jrD+K5Vu/gHTKEzWQoOOz0lHyARwJVANAlQv0aUabK3XZ6UgNUyL4q3DYFKYR\nOEW/MQSuBfUjUX5LYTq2/0Yet7hQPX/HOVsFGrHlO3hqA8Jf6UvzRjpn2tKA/5cK\n5GRYc1etAgMBAAECggEADsNXGZYEDbVJNL0+LsiGP2GjX9M9S9z+cSrcGqehmxwS\nYaUNDF4ZqbjO4Q77xkbUYKrRDASOQFbBimfmw0E8W91wc53ouFtoE2CetwJOZD0x\nOgSe/wsvMqJctm94GzchwZGglonRqwto2MG3+aZ4ATvYDjiDOjbgJZTg3jER8QpP\n89YmrDbdzwA/lSN61UpXrEP1oHimqQ66kOY0fcE6BAghYjBdtjXtSvyOAXtv5wB8\nLIJ2uj2zyWlqWzXqOBZfr9Hh9MOJ9PKldyxFajClezL1c6KjXbPpoux6RlyCRjJU\nsKdShwmRC/0tRG/wc2T+a4ua7k57cbE1UACzuzwfwQKBgQD4fheKclAI++lv+Thd\n0zHhf2PxOPbpAaf6WNd6VNRXb6I8DcYYdtRYQeBaeuQ4GBV/ydVQytoZ02QInpBT\njFp/3ucKib3ayXL2kB4qXeCN8GHiXl7uaQYQjn4Wx2C9F5ls9Jil2zXsM6aWTC9P\nFWSaLM2I0CWxA0vWPUub5ghtoQKBgQDdehVsFPT2fPDHUQNGPS/OGJ6GNBOqGsTd\nep+cgsk+d81El8Z7dsoOUR8TRjclD4KYWhRmBsjorhPnECE10ETDG5cVPVOmPbIv\nuldAL3QIvRqbpuFFCSmhDVYy584ryYsUgG6G5czDVHO8Djt4lzL+QG0elaoqqupG\nWfQmyk82jQKBgFIsIEzAEIdoBoHowCMGu+/92Gbkl4Hl8k5vIpJpiu5/E/8X7vIY\nGZA1+KLzEJUcIb/oVoopCoaPyPywsrluKF8wruZlNksrYsD2V4NbF+7YFwZsfqgI\nQuEmvbt6oxrkuu+00uXF38cELYp2Fw7n3CS/vBgJ/OzUUje+fUpIf3EBAoGBAIH0\nm9NSrLZhc4sQv0IcrwtYqNQIhK1gjbmDtVpJ57nu5BRmloFln4QtF3Xg0oS9iBzL\nZoLDYmodkvIXJdWEwoRVkR5WYNoAA6k7xuyTq5thEtbYYgB3MuUchULTf8dzuFcs\nUS54cuD+kfZ7x2uoFLTZqu2yVio5JcRoDfog5cAVAoGAA2QR0TR/jHVtW281hO3j\ngXXLD4yrByODSY7MqucJp1k3zESYyn4z41KhksG5W9EMtWFZ40/zH9UxHlmqm+p6\ny7UN2KMIcWr+Idna95G0bCYISXQaP/pm2H3xC4HVDOV1e1jZylEIViBeBcxWWjJE\nwpDgpTOfLIS6N81xJOKqKP4=\n-----END PRIVATE KEY-----\n",
  client_email: process.env.FIREBASE_CLIENT_EMAIL || "firebase-adminsdk-fbsvc@scanaraai.iam.gserviceaccount.com",
  client_id: process.env.FIREBASE_CLIENT_ID || "100972524767136876924",
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40scanaraai.iam.gserviceaccount.com",
  universe_domain: "googleapis.com"
};

// Initialize Firebase Admin if not already initialized
if (!admin.apps.length) {
  try {
    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount)
    });
    console.log('Firebase Admin SDK initialized successfully');
  } catch (error) {
    console.error('Error initializing Firebase Admin SDK:', error);
  }
}

// Export auth instance for token verification
export const auth = admin.auth();

// Export Firestore instance
export const db = admin.firestore();

