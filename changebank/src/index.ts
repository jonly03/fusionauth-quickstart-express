import FusionAuthClient, { UserRequest } from "@fusionauth/typescript-client";
import express, { Request, Response, NextFunction } from "express";
import cookieParser from "cookie-parser";
import pkceChallenge from "pkce-challenge";
import { GetPublicKeyOrSecret, verify } from "jsonwebtoken";
import jwksClient, { RsaSigningKey } from "jwks-rsa";
import { checkRole } from "./middleware";
import * as path from "path";

// Add environment variables
import * as dotenv from "dotenv";

dotenv.config();

const app = express();
const port = 8080; // default port to listen

if (!process.env.clientId) {
  console.error("Missing clientId from .env");
  process.exit();
}
if (!process.env.clientSecret) {
  console.error("Missing clientSecret from .env");
  process.exit();
}
if (!process.env.fusionAuthURL) {
  console.error("Missing clientSecret from .env");
  process.exit();
}

if (!process.env.apiKey) {
  console.error("Missing clientSecret from .env");
  process.exit();
}
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const fusionAuthURL = process.env.fusionAuthURL;
const fusionApiKey = process.env.apiKey;

// Validate the token signature, make sure it wasn't expired
const validateUser = async (userTokenCookie: { access_token: string }) => {
  // Make sure the user is authenticated.
  if (!userTokenCookie || !userTokenCookie?.access_token) {
    return false;
  }
  try {
    let decodedFromJwt;
    await verify(
      userTokenCookie.access_token,
      await getKey,
      undefined,
      (err, decoded) => {
        decodedFromJwt = decoded;
      }
    );
    return decodedFromJwt;
  } catch (err) {
    console.error(err);
    return false;
  }
};

const getKey: GetPublicKeyOrSecret = async (header, callback) => {
  const jwks = jwksClient({
    jwksUri: `${fusionAuthURL}/.well-known/jwks.json`,
  });
  const key = (await jwks.getSigningKey(header.kid)) as RsaSigningKey;
  var signingKey = key?.getPublicKey() || key?.rsaPublicKey;
  callback(null, signingKey);
};

//Cookies
const userSession = "userSession";
const userToken = "userToken";
const userDetails = "userDetails"; //Non Http-Only with user info (not trusted)

// Roles
const viewerRole = "Viewer";
const editorRole = "Editor";

const client = new FusionAuthClient(fusionApiKey, fusionAuthURL);

app.use(cookieParser());
/** Decode Form URL Encoded data */
app.use(express.urlencoded());

app.use("/static", express.static(path.join(__dirname, "../static/")));

app.get("/", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (await validateUser(userTokenCookie)) {
    res.redirect(302, "/account");
  } else {
    const stateValue =
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15) +
      Math.random().toString(36).substring(2, 15);
    const pkcePair = await pkceChallenge();
    res.cookie(
      userSession,
      {
        stateValue,
        verifier: pkcePair.code_verifier,
        challenge: pkcePair.code_challenge,
      },
      { httpOnly: true }
    );

    res.sendFile(path.join(__dirname, "../templates/home.html"));
  }
});

app.get("/login", (req, res, next) => {
  const userSessionCookie = req.cookies[userSession];

  // Cookie was cleared, just send back (hacky way)
  if (!userSessionCookie?.stateValue || !userSessionCookie?.challenge) {
    res.redirect(302, "/");
  }

  res.redirect(
    302,
    `${fusionAuthURL}/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=http://localhost:${port}/oauth-redirect&state=${userSessionCookie?.stateValue}&code_challenge=${userSessionCookie?.challenge}&code_challenge_method=S256`
  );
});

app.get("/oauth-redirect", async (req, res, next) => {
  // Capture query params
  const stateFromFusionAuth = `${req.query?.state}`;
  const authCode = `${req.query?.code}`;

  // Validate cookie state matches FusionAuth's returned state
  const userSessionCookie = req.cookies[userSession];
  if (stateFromFusionAuth !== userSessionCookie?.stateValue) {
    console.log("State doesn't match. uh-oh.");
    console.log(
      "Saw: " +
        stateFromFusionAuth +
        ", but expected: " +
        userSessionCookie?.stateValue
    );
    res.redirect(302, "/");
    return;
  }

  try {
    // Exchange Auth Code and Verifier for Access Token
    const accessToken = (
      await client.exchangeOAuthCodeForAccessTokenUsingPKCE(
        authCode,
        clientId,
        clientSecret,
        `http://localhost:${port}/oauth-redirect`,
        userSessionCookie.verifier
      )
    ).response;

    if (!accessToken.access_token) {
      console.error("Failed to get Access Token");
      return;
    }
    res.cookie(userToken, accessToken, { httpOnly: true });

    // Exchange Access Token for User
    const userResponse = (
      await client.retrieveUserUsingJWT(accessToken.access_token)
    ).response;
    if (!userResponse?.user) {
      console.error("Failed to get User from access token, redirecting home.");
      res.redirect(302, "/");
    }

    res.cookie(userDetails, userResponse.user);

    res.redirect(302, "/account");
  } catch (err: any) {
    console.error(err);
    res.status(err?.statusCode || 500).json(
      JSON.stringify({
        error: err,
      })
    );
  }
});

app.get("/account", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!(await validateUser(userTokenCookie))) {
    res.redirect(302, "/");
  } else {
    res.sendFile(path.join(__dirname, "../templates/account.html"));
  }
});

app.get("/make-change", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!(await validateUser(userTokenCookie))) {
    res.redirect(302, "/");
  } else {
    res.sendFile(path.join(__dirname, "../templates/make-change.html"));
  }
});

app.post("/make-change", checkRole, async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!(await validateUser(userTokenCookie))) {
    res.status(403).json(
      JSON.stringify({
        error: "Unauthorized",
      })
    );
    return;
  }

  let error;
  let message;

  var coins = {
    quarters: 0.25,
    dimes: 0.1,
    nickels: 0.05,
    pennies: 0.01,
  };

  try {
    message = "We can make change for";
    let remainingAmount = +req.body.amount;
    for (const [name, nominal] of Object.entries(coins)) {
      let count = Math.floor(remainingAmount / nominal);
      remainingAmount =
        Math.round((remainingAmount - count * nominal) * 100) / 100;

      message = `${message} ${count} ${name}`;
    }
    `${message}!`;
  } catch (ex: any) {
    error = `There was a problem converting the amount submitted. ${ex.message}`;
  }
  res.json(
    JSON.stringify({
      error,
      message,
    })
  );
});

app.get("/add-data", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!(await validateUser(userTokenCookie))) {
    res.redirect(302, "/");
  } else {
    res.sendFile(path.join(__dirname, "../templates/add-data.html"));
  }
});

app.post("/add-data", checkRole, async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!(await validateUser(userTokenCookie))) {
    res.status(403).json(
      JSON.stringify({
        error: "Unauthorized",
      })
    );
    return;
  }

  const userDetailsCookie = req.cookies[userDetails];
  if (!userDetailsCookie?.id) {
    console.log("user details cookie cleared. Weird");
    return res.redirect(302, "/");
  }

  const hobby = req.body?.hobby;
  const nickName = req.body?.nickname;

  const userReq: UserRequest = {
    user: {
      data: { hobby, nickName },
    },
  };

  let error;
  let message;

  try {
    message = await client.patchUser(userDetailsCookie.id, userReq);
  } catch (err) {
    error = err;
    console.log(err);
  }

  res.json(
    JSON.stringify({
      error,
      message,
    })
  );
});

app.get("/logout", (req, res, next) => {
  res.redirect(302, `${fusionAuthURL}/oauth2/logout?client_id=${clientId}`);
});

app.get("/oauth2/logout", (req, res, next) => {
  console.log("Logging out...");
  res.clearCookie(userSession);
  res.clearCookie(userToken);
  res.clearCookie(userDetails);

  res.redirect(302, "/");
});

app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});
