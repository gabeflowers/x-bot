// Import necessary modules
import axios from 'axios';
import qs from 'querystring';
import crypto from 'crypto';
import express from 'express';
import session from 'express-session';
import { createClient } from 'redis';
import { RedisStore } from 'connect-redis';
import dotenv from 'dotenv';

dotenv.config();

const SCOPES = 'tweet.read users.read follows.read tweet.write'; // Updated scopes

const API_BASE_URL = process.env.API_BASE_URL;
const AUTH_URL = process.env.AUTH_URL;
const TOKEN_URL = process.env.TOKEN_URL;
let ACCESS_TOKEN = null;

const app = express();

// Initialize Redis client
const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379',
});

redisClient.connect().catch(console.error);

redisClient.on('connect', () => console.log('Conectado ao Redis!'));
redisClient.on('error', (err) => console.error('Erro no Redis:', err));

// Initialize RedisStore
const redisStore = new RedisStore({
  client: redisClient,
  prefix: 'myapp:',
});

// Configure sessions with RedisStore
app.use(
  session({
    store: redisStore,
    secret: process.env.SESSION_SECRET || 'change-this-in-production',
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
    },
  })
);

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Aplicação funcionando!');
});

const generatePKCE = () => {
  const codeVerifier = crypto.randomBytes(43).toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  const codeChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return { codeVerifier, codeChallenge };
};

function getAuthorizationURL(req) {
  const state = crypto.randomBytes(16).toString('hex');
  const { codeVerifier, codeChallenge } = generatePKCE();

  req.session.state = state;
  req.session.codeVerifier = codeVerifier;

  const query = {
    response_type: 'code',
    client_id: process.env.CLIENT_ID,
    redirect_uri: process.env.REDIRECT_URI.trim(),
    scope: SCOPES,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: state,
  };

  console.log('Generated Authorization URL:', `${AUTH_URL}?${qs.stringify(query)}`);
  return `${AUTH_URL}?${qs.stringify(query)}`;
}

async function exchangeAuthorizationCode(req, code) {
  try {
    const { CLIENT_ID, CLIENT_SECRET, REDIRECT_URI } = process.env;
    if (!CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
      throw new Error('Environment variables CLIENT_ID, CLIENT_SECRET, and REDIRECT_URI must be set.');
    }

    if (!req.session || !req.session.codeVerifier) {
      throw new Error('Session or code verifier is missing. Authorization flow may be incomplete.');
    }

    const base64Credentials = Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString('base64');

    const requestBody = qs.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI.trim(),
      code_verifier: req.session.codeVerifier,
    });

    const response = await axios.post(TOKEN_URL, requestBody, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${base64Credentials}`,
      },
      timeout: 10000,
    });

    if (!response.data.access_token) {
      throw new Error('Access token not found in the response.');
    }

    const { access_token: accessToken, refresh_token: refreshToken } = response.data;
    ACCESS_TOKEN = accessToken;

    console.log('Access Token obtained:', ACCESS_TOKEN);

    if (refreshToken) {
      console.log('Refresh Token obtained:', refreshToken);
    }

    return ACCESS_TOKEN;
  } catch (error) {
    if (error.response) {
      console.error('HTTP Error:', error.response.status, error.response.statusText);
      console.error('Error Details:', error.response.data);
    } else if (error.request) {
      console.error('No response received from the server:', error.message);
    } else {
      console.error('Error:', error.message);
    }
    throw error;
  }
}

app.get('/login', (req, res) => {
  const authURL = getAuthorizationURL(req);
  res.redirect(authURL);
});

app.get('/callback', async (req, res) => {
  const { code, state } = req.query;

  console.log('Callback received:');
  console.log('Code:', code);
  console.log('State:', state);
  console.log('Session state:', req.session?.state);

  if (!code) {
    return res.status(400).send('Authorization code is missing.');
  }

  if (!req.session.state || state !== req.session.state) {
    console.error('State mismatch or missing.');
    return res.status(400).send('Invalid state. Potential CSRF detected.');
  }

  try {
    await exchangeAuthorizationCode(req, code);
    res.send('Authentication successful! Access token is stored.');
  } catch (error) {
    console.error('Error exchanging authorization code:', error);
    res.status(500).send('Error obtaining access token.');
  }
});

app.get('/post-tweet', async (req, res) => {
  if (!ACCESS_TOKEN) {
    return res.status(401).send('Access token not available. Please authenticate first.');
  }


  // const { text } = req.body; 
  // if (!text) {
  //   return res.status(400).send('Tweet text is required.');
  // }

  const text = 'Hello World 😎'

  try {
    const response = await axios.post(
      `${API_BASE_URL}/tweets`,
      { text },
      {
        headers: {
          Authorization: `Bearer ${ACCESS_TOKEN}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Error posting tweet:', error.response?.data || error.message);
    res.status(500).send('Error posting tweet.');
  }
});

const PORT = process.env.PORT || 3500;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running at http://localhost:${PORT}`);
  console.log(`Visit http://localhost:${PORT}/login to start the authorization flow.`);
});