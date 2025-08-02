const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 3000;

// Middleware para registrar logs
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Protección: limitar 100 peticiones por hora por IP
const limiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hora
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

// Ruta de log para registrar IPs
app.post('/log', (req, res) => {
    const { event, ip } = req.body;

    // Validar que los datos sean correctos
    if (!ip || !event) {
        return res.status(400).json({ error: 'Faltan datos en la solicitud' });
    }

    const logText = `[${new Date().toLocaleString()}] Evento: ${event}, IP: ${ip}\n`;
    console.log(logText);

    // Guardar en archivo de logs
    try {
        fs.appendFileSync('logs.txt', logText);
        res.status(200).json({ status: 'ok' });
    } catch (err) {
        console.error('Error al escribir en el archivo de logs:', err);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Ruta protegida de admin
const adminCredentials = {
    username: 'an',
    password: 'tumama123_+'
};

app.post('/admin', (req, res) => {
    const { us, ps } = req.body;
    if (us === adminCredentials.username && ps === adminCredentials.password) {
        return res.status(200).json({ message: 'Bienvenido, admin autorizado.' });
    } else {
        const logText = `[${new Date().toLocaleString()}] ⚠️ Intento NO autorizado desde IP ${req.ip} con user=${us}\n`;
        console.warn(logText);
        fs.appendFileSync('logs.txt', logText);
        return res.status(403).json({ message: 'Acceso denegado.' });
    }
});

// Middleware de seguridad avanzada para detectar cambios sospechosos
app.use((req, res, next) => {
    const headers = JSON.stringify(req.headers);
    if (headers.includes('burp') || headers.includes('scanner') || headers.includes('sqlmap')) {
        const logText = `[${new Date().toLocaleString()}] ❌ Posible intento de escaneo desde IP ${req.ip}\n`;
        fs.appendFileSync('logs.txt', logText);
        return res.status(403).send('Bloqueado por actividad sospechosa.');
    }
    next();
});

// Manejo de errores genéricos
app.use((err, req, res, next) => {
    console.error('Error en el servidor:', err);
    const logText = `[${new Date().toLocaleString()}] ❌ Error en el servidor desde IP ${req.ip}: ${err.message}\n`;
    fs.appendFileSync('logs.txt', logText);
    res.status(500).json({ error: 'Error interno del servidor' });
});

app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
