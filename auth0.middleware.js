const { auth, claimCheck } = require("express-oauth2-jwt-bearer");
const jwksRsa = require("jwks-rsa");
const authConfig = require("./src/auth_config.json");

const secret = jwksRsa.expressJwtSecret({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
});

//console.log(secret)
console.log(`https://${authConfig.domain}/.well-known/jwks.json`)

const validateAccessToken = auth({
  issuer: `https://${authConfig.domain}/`,
  audience: authConfig.audience,
  //secret,
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 5,
  jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
});

const checkRequiredPermissions = (requiredPermissions) => {
  return (req, res, next) => {
    const permissionCheck = claimCheck((payload) => {
      const permissions = payload.permissions || [];

      return requiredPermissions.every((requiredPermission) =>
        permissions.includes(requiredPermission)
      );
    }, "Permission denied");

    permissionCheck(req, res, next);
  };
};

module.exports = {
  validateAccessToken,
  checkRequiredPermissions,
};