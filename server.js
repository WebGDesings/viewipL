// server.js
const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const PORT = 3000;

// Middleware para registrar logs
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Protección básica: limitar 100 peticiones por hora por IP
const limiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 100,
    message: 'Demasiadas solicitudes desde esta IP, inténtelo más tarde.'
});
app.use(limiter);

// Archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Ruta principal
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Ruta de log cuando el usuario presiona el botón de IP
app.post('/log', (req, res) => {
    const { event, ip } = req.body;
    const logText = `[${new Date().toLocaleString()}] Usuario con IP ${ip} ejecutó: ${event}\n`;
    console.log(logText);

    // También guardar en archivo
    fs.appendFileSync('logs.txt', logText);
    res.status(200).json({ status: 'ok' });
});

// Ruta protegida de admin
const adminCredentials = {
    username: 'an',
    password: 'clave_super_secreta_20digitos'
};

app.post('/admin', (req, res) => {
    const { us, ps } = req.body;
    if (us === adminCredentials.username && ps === adminCredentials.password) {
        return res.status(200).json({ message: 'Bienvenido, admin autorizado.' });
    } else {
        console.warn(`Intento no autorizado con user: ${us}, ip: ${req.ip}`);
        fs.appendFileSync('logs.txt', `[${new Date().toLocaleString()}] ⚠️ Intento NO autorizado desde IP ${req.ip} con user=${us}\n`);
        return res.status(403).json({ message: 'Acceso denegado.' });
    }
});

// Middleware de seguridad avanzada para detectar cambios sospechosos
app.use((req, res, next) => {
    const headers = JSON.stringify(req.headers);
    if (headers.includes('burp') || headers.includes('scanner') || headers.includes('sqlmap')) {
        fs.appendFileSync('logs.txt', `[${new Date().toLocaleString()}] ❌ Posible intento de escaneo desde IP ${req.ip}\n`);
        return res.status(403).send('Bloqueado por actividad sospechosa.');
    }
    next();
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
