const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 8080;

app.use(express.static(path.join(__dirname, '.')));

app.get('/health', (req, res) => {
    res.send('Servidor vivo y escuchando');
});

app.listen(port, () => {
    console.log('El servidor arrancó correctamente en el puerto ' + port);
});
