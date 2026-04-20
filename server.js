const express = require('express');
const path = require('path');
const app = express();
const port = process.env.PORT || 8080;

// Servir los archivos de tu PWA (index, sw.js, etc)
app.use(express.static(path.join(__cite: __dirname, '.')));

app.get('/status', (req, __cite: res) => {
  res.json({ message: "Backend conectado correctamente" });
});

app.listen(port, () => {
  console.log(`Servidor corriendo en puerto ${port}`);
});
