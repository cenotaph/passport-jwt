var Strategy = require('../lib/strategy')
    , chai = require('chai')
    , test_data = require('./testdata')
    , sinon = require('sinon')
    , extract_jwt = require('../lib/extract_jwt');
var jwt = require('jsonwebtoken');

//var token = jwt.sign({ foo: 'bar' }, privateKey, { algorithm: 'RS256'});


var createStrategy = function(){

    
        
    config1 = {};
    config1.issuer = "TestIssuer1";
    config1.secretOrKey = 'secret1';
    config1.ignoreExpiration = false;
    config1.jwtFromRequest = extract_jwt.fromAuthHeaderAsBearerToken();

    config2 = { 
        jwtFromRequest: extract_jwt.fromAuthHeaderAsBearerToken(),
        ignoreExpiration: false,
        secretOrKeyProvider: sinon.spy(function(request, token, done) {
            done(null, 'secret2');
        })
    };


    return new Strategy([config1,config2],  function(jwt_payload, done) {
        err = null;
        user = {name:"hello"};
        info = {some:"hello"};
        return done(err, user,info);
    });

}

var runWith = function(result,payload,strategy,secret,done){

    

    chai.passport.use(strategy)
            .req(function(req) {
                var token = jwt.sign(payload, secret, { algorithm: 'HS256'})
                req.headers['authorization'] = "bearer " +token;
            })
            .success(function(u, i) {
                result.push(true);
                done();
            })
            .error(function(u) {
                console.log("error",u);
                done();
            })
            .fail(function(u ) {
                done();
            })
            .authenticate(); 
    
}

describe('Multi Strategy', function() {

    describe('calling secret config with issuer', function() {
        var strategy;
        var result = [];  
        before(function(done) {

            payload = {
                "sub": "1234567890",
                "name": "John Doe",
                "iss": "TestIssuer1",
            }

            strategy = createStrategy()

            runWith(result,payload,strategy,'secret1',done);           
        });

        it('should provide a user', function() {    
            expect(result.length).to.equal(1);
        });

    });

});

describe('Multi Strategy', function() {

    describe('calling secret config with issuer fail', function() {
        var strategy;
        var result = [];  
        before(function(done) {

            payload = {
                "sub": "1234567890",
                "name": "John Doe",
            }

            strategy = createStrategy()

            runWith(result,payload,strategy,'secret1',done);           
        });

        it('should provide a user', function() {    
            expect(result.length).to.equal(0);
        });

    });

});

describe('Multi Strategy', function() {

    describe('calling secretProvider config ', function() {
        var strategy;
        var result = [];  
        before(function(done) {

            payload = {
                "sub": "1234567890",
                "name": "John Doe",
            }

            strategy = createStrategy()

            runWith(result,payload,strategy,'secret2',done);           
        });

        it('should provide a user', function() {    
            expect(result.length).to.equal(1);
        });

    });

});
