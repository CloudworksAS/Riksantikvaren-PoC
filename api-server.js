const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const helmet = require("helmet");
const jwt = require("express-jwt");
const jwksRsa = require("jwks-rsa");
const authConfig = require("./src/auth_config.json");
const { validateAccessToken, checkRequiredPermissions } = require('./auth0.middleware')

const app = express();

const port = process.env.API_PORT || 3001;
const appPort = process.env.SERVER_PORT || 3000;
const appOrigin = authConfig.appOrigin || `http://localhost:${appPort}`;

if (
  !authConfig.domain ||
  !authConfig.audience ||
  authConfig.audience === "YOUR_API_IDENTIFIER"
) {
  console.log(
    "Exiting: Please make sure that auth_config.json is in place and populated with valid domain and audience values"
  );

  process.exit();
}

app.use(morgan("dev"));
app.use(helmet());
app.use(cors({ origin: appOrigin }));

const checkJwt = jwt({
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithms: ["RS256"],
});


app.get("/api/:fylke/:kommune/:type_minne/:navn_paa_minne", (req, res) => {
  const namespace = 'https://riksantikvaren.no/'
  const {fylke, kommune, type_minne, navn_paa_minne} = req.params
  const requiredPermission = `helelandet_${fylke}_${kommune}_${type_minne}_${navn_paa_minne}`
  const permissions = req.auth.token[`${namespace}askeladdenPermissions`]

  var haveAccess = false
  permissions.every(permission => {
    if (requiredPermission.startsWith(permission)) {
      haveAccess = true
      return false
    }
    return true
  });

  if (!haveAccess) {
    res.send(403)
    return;
  }

  // if get here, we have access to the requested resource
});

app.get("/api/external", validateAccessToken, async (req, res) => {

  const id = req.auth.payload.sub

  res.send({
    msg: "Your access token was successfully validated!",
    token_claims: req.auth.payload,
    //organizations,
  });
});


app.get("/api/approve", validateAccessToken, checkRequiredPermissions(['approver']), async (req, res) => {

  // TODO make descisions based on customer specific scopes in req.user.permissions

  res.send({
    msg: "Your access token was successfully validated at the approve endpoint!",
    token_claims: req.auth.payload,
  });
});

app.listen(port, () => console.log(`API Server listening on port ${port}`));
