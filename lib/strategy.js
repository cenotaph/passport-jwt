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

        configItem._passReqToCallback = options.passReqToCallback;
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
    let fails = [];
    let errors = [];
    let success = null;
    
    async.each(self._config, function (configItem, callback) {
        if (success) {
            return;
        }
        var token = configItem._jwtFromRequest(req);

        if (!token) {
            return self.fail(new Error("No auth token"));
        }

        configItem._secretOrKeyProvider(req, token, function (secretOrKeyError, secretOrKey) {
            if (secretOrKeyError) {
                fails.push(secretOrKeyError)
                // if (fails.length + errors.length == self._config.length) {
                //     if (self._config.length == 1) {
                //        return errors.length > 0 ? self.error(errors[0]) : self.fail(fails[0]);
                        
                //     }

                //     const allErrors = errors.concat(fails);
                //     if (errors.length > 0) {
                //         self.error(allErrors);
                //     }
                //     else {
                //         self.fail(allErrors);
                //     }
                // }

            } else {
                // Verify the JWT
                JwtStrategy.JwtVerifier(token, secretOrKey, configItem._verifOpts, function (jwt_err, payload) {
                    if (jwt_err) {
                        fails.push(jwt_err);

                        // if (fails.length + errors.length == self._config.length) {
                        //     if (self._config.length == 1) {
                        //         if (errors.length > 0) {
                        //              self.error(errors[0]);
                        //         }
                        //         else {
                        //             self.fail(fails[0]);
                        //         }
                        //     }

                        //     const allErrors = errors.concat(fails);
                        //     if (errors.length > 0) {
                        //         self.error(allErrors);
                        //     }
                        //     else {
                        //         self.fail(allErrors);
                        //     }
                        // }

                    } else {
                        // Pass the parsed token to the user, or add errors/fails to the fails array before returning
                        var verified = function (err, user, info) {
                            if (err) {
                                errors.push(err);
                            } else if (!user) {
                                fails.push(info);
                            } else {
                                success = info;
                                return self.success(user, info);
                            }

                            // if (fails.length + errors.length == self._config.length) {
                            //     if (self._config.length == 1) {
                            //        return errors.length > 0 ? self.error(errors[0]) : self.fail(fails[0]);
                            //     }
            
                            //     const allErrors = errors.concat(fails);
                            //     if (errors.length > 0) {
                            //         return self.error(allErrors);
                            //     }
                            //     else {
                            //         return self.fail(allErrors);
                            //     }
                            // }
            
                        }

                        

                        try {
                            if (configItem._passReqToCallback) {
                                configItem._verify(req, payload, verified);
                            } else {
                                configItem._verify(payload, verified);
                            }
                        } catch (ex) {
                            self.error(ex);
                        }
                    }
                });
            }
        });
    });

    if (fails.length + errors.length == self._config.length) {
        if (self._config.length == 1) {
            if (errors.length > 0) {
                return self.error(errors[0]);
            }
            else {
               return self.fail(fails[0]);
            }
        }

        const allErrors = errors.concat(fails);
        if (errors.length > 0) {
           return self.error(allErrors);
        }
        else {
           return self.fail(allErrors);
        }
    }

};



/**
 * Export the Jwt Strategy
 */
module.exports = JwtStrategy;
