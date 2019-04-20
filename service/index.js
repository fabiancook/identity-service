import express from "express";
import level from "level";
import ttl from "level-ttl";
import createCredentialsHandler from "./handlers/create-credentials";
import exchangeCredentialsHandler from "./handlers/exchange-credentials";
import bearer from "./middleware/verify-bearer.js";

const app = express();

app.locals.store = level("./store");
app.locals.ttl = ttl(app.locals.store);

app.post("/create-credentials", createCredentialsHandler);
app.post("/exchange-credentials", exchangeCredentialsHandler);
app.get("/check-authentication", bearer, (request, response) => response.send("You're authenticated!"));

// IIFE so we don't need to define `port` as `let` ¯\_(ツ)_/¯
const port = (() => {
  if (/^\d+$/.test(process.env.PORT)) {
  	return +process.env.PORT;  
  }
  // Maybe you have other defaults you want to check here to decide on the port
  return 8080;
})();

app.listen(port, () => console.log(`Listening on ${port}`));