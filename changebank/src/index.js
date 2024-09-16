"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var typescript_client_1 = require("@fusionauth/typescript-client"); // to exchange OAuth Code for Access Token using PKCE & retrieving User using JWT
var express_1 = require("express");
var cookie_parser_1 = require("cookie-parser");
var pkce_challenge_1 = require("pkce-challenge");
var jsonwebtoken_1 = require("jsonwebtoken");
var jwks_rsa_1 = require("jwks-rsa");
var path = require("path");
// Add environment variables
var dotenv = require("dotenv");
dotenv.config();
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
var _a = process.env, clientId = _a.clientId, clientSecret = _a.clientSecret, fusionAuthURL = _a.fusionAuthURL;
var app = (0, express_1.default)();
app.use((0, cookie_parser_1.default)()); // Parse Cookie header and populate req.cookies
app.use(express_1.default.urlencoded()); // Decode Form URL encoded data
var port = 8080;
// Cookies
var userSession = "userSession";
var userToken = "userToken";
var userDetails = "userDetails";
// Validate the token signature, make sure it wasn't expired
var validateUser = function (userTokenCookie) { return __awaiter(void 0, void 0, void 0, function () {
    var decodedFromJwt_1, _a, _b, err_1;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                // Make sure the user is authenticated.
                if (!userTokenCookie || !(userTokenCookie === null || userTokenCookie === void 0 ? void 0 : userTokenCookie.access_token)) {
                    return [2 /*return*/, false];
                }
                _c.label = 1;
            case 1:
                _c.trys.push([1, 4, , 5]);
                _a = jsonwebtoken_1.verify;
                _b = [userTokenCookie.access_token];
                return [4 /*yield*/, getKey];
            case 2: return [4 /*yield*/, _a.apply(void 0, _b.concat([_c.sent(), undefined,
                    function (err, decoded) {
                        decodedFromJwt_1 = decoded;
                    }]))];
            case 3:
                _c.sent();
                return [2 /*return*/, decodedFromJwt_1];
            case 4:
                err_1 = _c.sent();
                console.error(err_1);
                return [2 /*return*/, false];
            case 5: return [2 /*return*/];
        }
    });
}); };
var getKey = function (header, callback) { return __awaiter(void 0, void 0, void 0, function () {
    var jwks, key, signingKey;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                jwks = (0, jwks_rsa_1.default)({
                    jwksUri: "".concat(fusionAuthURL, "/.well-known/jwks.json"),
                });
                return [4 /*yield*/, jwks.getSigningKey(header.kid)];
            case 1:
                key = (_a.sent());
                signingKey = (key === null || key === void 0 ? void 0 : key.getPublicKey()) || (key === null || key === void 0 ? void 0 : key.rsaPublicKey);
                callback(null, signingKey);
                return [2 /*return*/];
        }
    });
}); };
var client = new typescript_client_1.default("noapikeyneeded", fusionAuthURL);
// GET /
app.get("/", function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userTokenCookie, stateValue, pkcePair;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                userTokenCookie = req.cookies[userToken];
                return [4 /*yield*/, validateUser(userTokenCookie)];
            case 1:
                if (!_a.sent()) return [3 /*break*/, 2];
                res.redirect(302, "/account");
                return [3 /*break*/, 4];
            case 2:
                stateValue = Math.random().toString(36).substring(2, 15) +
                    Math.random().toString(36).substring(2, 15) +
                    Math.random().toString(36).substring(2, 15) +
                    Math.random().toString(36).substring(2, 15) +
                    Math.random().toString(36).substring(2, 15) +
                    Math.random().toString(36).substring(2, 15);
                return [4 /*yield*/, (0, pkce_challenge_1.default)()];
            case 3:
                pkcePair = _a.sent();
                res.cookie(userSession, {
                    stateValue: stateValue,
                    verifier: pkcePair.code_verifier,
                    challenge: pkcePair.code_challenge,
                }, { httpOnly: true });
                res.sendFile(path.join(__dirname, "../templates/home.html"));
                _a.label = 4;
            case 4: return [2 /*return*/];
        }
    });
}); });
// GET /login
// Begin the Authorization Code Grant.
// Redirect to FusionAuth Authorization endpoint with response_type=code
// Provide redirection endpoint where to send the code to -- (OAuth configuration -> Authorized redirects)
// Use PKCE to mitigate MITM vulnerability, enhance the confidentiality and integrity of the code, and ensure client is genuine
// Send Authorization Server the code_challenge now, verify later at the redirection endpoint
app.get("/login", function (req, res, next) {
    var userSessionCookie = req.cookies[userSession];
    // Cookie was cleared on /logout
    // Redirect to / to reset
    // TODO: give our cookies a maxAge
    if (!(userSessionCookie === null || userSessionCookie === void 0 ? void 0 : userSessionCookie.stateValue) || !(userSessionCookie === null || userSessionCookie === void 0 ? void 0 : userSessionCookie.challenge)) {
        res.redirect(302, "/");
    }
    res.redirect(302, "".concat(fusionAuthURL, "/oauth2/authorize?client_id=").concat(clientId, "&response_type=code&redirect_uri=http://locahost:").concat(port, "/oauth-redirect&state=").concat(userSessionCookie === null || userSessionCookie === void 0 ? void 0 : userSessionCookie.stateValue, "&code_challenge=").concat(userSessionCookie === null || userSessionCookie === void 0 ? void 0 : userSessionCookie.challenge, "&code_challenge_method=S256"));
});
app.get("/oauth-redirect", function (req, res, next) { return __awaiter(void 0, void 0, void 0, function () {
    var stateFromFusionAuth, authCode, userSessionCookie, accessToken, userResponse, err_2;
    var _a, _b;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                stateFromFusionAuth = "".concat((_a = req.query) === null || _a === void 0 ? void 0 : _a.state);
                authCode = "".concat((_b = req.query) === null || _b === void 0 ? void 0 : _b.code);
                userSessionCookie = req.cookies[userSession];
                if (stateFromFusionAuth !== (userSessionCookie === null || userSessionCookie === void 0 ? void 0 : userSessionCookie.stateValue)) {
                    console.log("State doesn't match. uh-oh.");
                    console.log("Saw: " +
                        stateFromFusionAuth +
                        ", but expected: " +
                        (userSessionCookie === null || userSessionCookie === void 0 ? void 0 : userSessionCookie.stateValue));
                    res.redirect(302, "/");
                    return [2 /*return*/];
                }
                _c.label = 1;
            case 1:
                _c.trys.push([1, 4, , 5]);
                return [4 /*yield*/, client.exchangeOAuthCodeForAccessTokenUsingPKCE(authCode, clientId, clientSecret, "http://localhost:".concat(port, "/oauth-redirect"), userSessionCookie.verifier)];
            case 2:
                accessToken = (_c.sent()).response;
                if (!accessToken.access_token) {
                    console.error("Failed to get Access Token");
                    return [2 /*return*/];
                }
                res.cookie(userToken, accessToken, { httpOnly: true });
                return [4 /*yield*/, client.retrieveUserUsingJWT(accessToken.access_token)];
            case 3:
                userResponse = (_c.sent()).response;
                if (!(userResponse === null || userResponse === void 0 ? void 0 : userResponse.user)) {
                    console.error("Failed to get User from access token, redirecting home.");
                    res.redirect(302, "/");
                }
                res.cookie(userDetails, userResponse.user);
                res.redirect(302, "/account");
                return [3 /*break*/, 5];
            case 4:
                err_2 = _c.sent();
                console.error(err_2);
                res.status((err_2 === null || err_2 === void 0 ? void 0 : err_2.statusCode) || 500).json(JSON.stringify({
                    error: err_2,
                }));
                return [3 /*break*/, 5];
            case 5: return [2 /*return*/];
        }
    });
}); });
app.get("/account", function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userTokenCookie;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                userTokenCookie = req.cookies[userToken];
                return [4 /*yield*/, validateUser(userTokenCookie)];
            case 1:
                if (!(_a.sent())) {
                    res.redirect(302, "/");
                }
                else {
                    res.sendFile(path.join(__dirname, "../templates/account.html"));
                }
                return [2 /*return*/];
        }
    });
}); });
app.get("/make-change", function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userTokenCookie;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                userTokenCookie = req.cookies[userToken];
                return [4 /*yield*/, validateUser(userTokenCookie)];
            case 1:
                if (!(_a.sent())) {
                    res.redirect(302, "/");
                }
                else {
                    res.sendFile(path.join(__dirname, "../templates/make-change.html"));
                }
                return [2 /*return*/];
        }
    });
}); });
app.post("/make-change", function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
    var userTokenCookie, error, message, coins, remainingAmount, _i, _a, _b, name_1, nominal, count;
    return __generator(this, function (_c) {
        switch (_c.label) {
            case 0:
                userTokenCookie = req.cookies[userToken];
                return [4 /*yield*/, validateUser(userTokenCookie)];
            case 1:
                if (!(_c.sent())) {
                    res.status(403).json(JSON.stringify({
                        error: "Unauthorized",
                    }));
                    return [2 /*return*/];
                }
                coins = {
                    quarters: 0.25,
                    dimes: 0.1,
                    nickels: 0.05,
                    pennies: 0.01,
                };
                try {
                    message = "We can make change for";
                    remainingAmount = +req.body.amount;
                    for (_i = 0, _a = Object.entries(coins); _i < _a.length; _i++) {
                        _b = _a[_i], name_1 = _b[0], nominal = _b[1];
                        count = Math.floor(remainingAmount / nominal);
                        remainingAmount =
                            Math.round((remainingAmount - count * nominal) * 100) / 100;
                        message = "".concat(message, " ").concat(count, " ").concat(name_1);
                    }
                    "".concat(message, "!");
                }
                catch (ex) {
                    error = "There was a problem converting the amount submitted. ".concat(ex.message);
                }
                res.json(JSON.stringify({
                    error: error,
                    message: message,
                }));
                return [2 /*return*/];
        }
    });
}); });
app.get("/logout", function (req, res, next) {
    res.redirect(302, "".concat(fusionAuthURL, "/oauth2/logout?client_id=").concat(clientId));
});
app.get("/oauth2/logout", function (req, res, next) {
    console.log("Logging out...");
    res.clearCookie(userSession);
    res.clearCookie(userToken);
    res.clearCookie(userDetails);
    res.redirect(302, "/");
});
app.listen(port, function () {
    console.log("server started at http://localhost:".concat(port));
});
