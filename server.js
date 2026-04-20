const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 8080;

app.use(express.json());
app.use(express.static(path.join(__dirname, '.')));

// Ruta de prueba para verificar que el servidor vive
app.get('/test', (req, res) => {
    res.send("Servidor funcionando correctamente");
});

app.listen(port, () => {
    console.log("Servidor Online en puerto " + port);
});
