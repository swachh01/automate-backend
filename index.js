const express = require("express");
const app = express();

app.use(express.json());

// Healthcheck route
app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

// Test route
app.get("/", (req, res) => {
  res.send("Backend running fine 🚀");
});

// Port from Railway
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

