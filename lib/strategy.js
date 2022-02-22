var passport = require('passport-strategy')
    , auth_hdr = require('./auth_header')
    , util = require('util')
    , url = require('url')
    , assign = require('./helpers/assign.js');
var async = require('async');



/**
 * Strategy constructor
 *
 * @param options
 *          secretOrKey: String or buffer containing the secret or PEM-encoded public key. Required unless secretOrKeyProvider is provided.
 *          secretOrKeyProvider: callback in the format secretOrKeyProvider(request, rawJwtToken, done)`,
 *                               which should call done with a secret or PEM-encoded public key
 *                               (asymmetric) for the given undecoded jwt token string and  request
 *                               combination. done has the signature function done(err, secret).
 *                               REQUIRED unless `secretOrKey` is provided.
 *          jwtFromRequest: (REQUIRED) Function that accepts a reqeust as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the, the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
function JwtStrategy(options, verify) {
    // for backwards compatibility with passport-jwt
    // options does not need to be an array
    if (!Array.isArray(options)) {
        options = [options];
    }
    passport.Strategy.call(this);
    this.name = 'jwt';
    this._config = new Array(options.length);
    for (let i = 0; i < options.length; i++) {
        const optionsItem = options[i];
        this._config[i] = {};
        let configItem = this._config[i];
        configItem._secretOrKeyProvider = optionsItem.secretOrKeyProvider;

        if (optionsItem.secretOrKey) {
            if (configItem._secretOrKeyProvider) {
                throw new TypeError('JwtStrategy has been given both a secretOrKey and a secretOrKeyProvider');
            }
            configItem._secretOrKeyProvider = function (request, rawJwtToken, done) {
                done(null, optionsItem.secretOrKey)
            };
        }

        if (!configItem._secretOrKeyProvider) {
            throw new TypeError('JwtStrategy requires a secret or key');
        }

        configItem._verify = verify;
        if (!configItem._verify) {
            throw new TypeError('JwtStrategy requires a verify callback');
        }

        configItem._jwtFromRequest = optionsItem.jwtFromRequest;
        if (!configItem._jwtFromRequest) {
            throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
        }

        configItem._passReqToCallback = optionsItem.passReqToCallback;
        var jsonWebTokenOptions = optionsItem.jsonWebTokenOptions || {};
        //for backwards compatibility, still allowing you to pass
        //audience / issuer / algorithms / ignoreExpiration
        //on the options.
        configItem._verifOpts = assign({}, jsonWebTokenOptions, {
            audience: optionsItem.audience,
            issuer: optionsItem.issuer,
            algorithms: optionsItem.algorithms,
            ignoreExpiration: !!optionsItem.ignoreExpiration
        });
        // return configItem;
    };
}
util.inherits(JwtStrategy, passport.Strategy);



/**
 * Allow for injection of JWT Verifier.
 *
 * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
 * process from failures in the passport related mechanics of authentication.
 *
 * Note that this should only be replaced in tests.
 */
JwtStrategy.JwtVerifier = require('./verify_jwt');



/**
 * Authenticate request based on JWT obtained from header or post body
 */
JwtStrategy.prototype.authenticate = function (req, options) {
    var self = this;
    var promises = [];
    self._config.forEach(function(configItem){

        promises.push(new Promise((resolve, reject) => {
        
            var token = configItem._jwtFromRequest(req);

            if (!token) {
                reject({error:new Error("No auth token"),cause:"fail"});
            }else{

                configItem._secretOrKeyProvider(req, token, function(secretOrKeyError, secretOrKey) {
                    if (secretOrKeyError) {
                        reject({error:secretOrKeyError,cause:"fail"})
                    } else {
                        // Verify the JWT
                        JwtStrategy.JwtVerifier(token, secretOrKey, configItem._verifOpts, function(jwt_err, payload) {
                            if (jwt_err) {
                                reject({error:jwt_err,cause:"fail"});
                            } else {
                                // Pass the parsed token to the user
                                var verified = function(err, user, info) {
                                    if(err) {
                                        reject({error:err,cause:"error"});
                                    } else if (!user) {
                                        reject({error:info,cause:"fail"});
                                    } else {
                                        resolve({user:user, info:info});
                                    }
                                };

                                try {
                                    if (configItem._passReqToCallback) {
                                        configItem._verify(req, payload, verified);
                                    } else {
                                        configItem._verify(payload, verified);
                                    }
                                } catch(ex) {
                                    reject({error:ex,cause:"error"});
                                }
                            }
                        });
                    }
                });
            }
        }));
    });

    Promise.any(promises).then(function(data){
        self.success(data.user,data.info);
    }).catch(function(errors){
        var errObject = errors.errors[0];
        if(errObject.cause == "fail"){
            self.fail(errObject.error);
        }else if(errObject.cause == "error"){
            self.error(errObject.error);
        }       
    });

};

/**
 * Export the Jwt Strategy
 */
module.exports = JwtStrategy;
