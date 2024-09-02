const express = require('express');
const morgan = require("morgan");
const { createProxyMiddleware } = require('http-proxy-middleware');

// Create Express Server
const app = express();

// Configuration
const PORT = 3000;
const HOST = "127.0.0.1";
const API_SERVICE_URL = "https://jsonplaceholder.typicode.com";
const SERVER1 = "http://10.0.1.1:8000/";
const SERVER2 = "http://10.0.2.1:8000/";
const SERVER3 = "http://10.0.3.1:8000/";
const SERVER4 = "http://10.0.4.1:8000/";

// Logging
app.use(morgan('dev'));


// Info GET endpoint
app.get('/info', (req, res, next) => {
    res.send('This is a proxy service.');
 });

// Proxy endpoints
app.use('/server1', createProxyMiddleware({
    target: SERVER1,
    changeOrigin: true,
    pathRewrite: {
        [`^/server1`]: '',
    },
    headers: {
        Connection: 'keep-alive'
    }
}));

app.use('/server2', createProxyMiddleware({
    target: SERVER2,
    changeOrigin: true,
    pathRewrite: {
        [`^/server2`]: '',
    },
    headers: {
        Connection: 'keep-alive'
    }
}));

app.use('/server3', createProxyMiddleware({
    target: SERVER3,
    changeOrigin: true,
    pathRewrite: {
        [`^/server3`]: '',
    },
    headers: {
        Connection: 'keep-alive'
    }
}));

app.use('/server4', createProxyMiddleware({
    target: SERVER4,
    changeOrigin: true,
    pathRewrite: {
        [`^/server4`]: '',
    },
    headers: {
        Connection: 'keep-alive'
    }
}));

// Start the Proxy
app.listen(PORT, HOST, () => {
    console.log(`Starting Proxy at ${HOST}:${PORT}`);
 });