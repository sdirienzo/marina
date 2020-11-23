const express = require('express');
const app = express();

const {Datastore} = require('@google-cloud/datastore');

const handlebars = require('express-handlebars').create({defaultLayout: 'main'});
const bodyParser = require('body-parser');
const request = require("request");

const datastore = new Datastore();

const jwt = require('express-jwt');
const jwksRsa = require('jwks-rsa');
const jwtDecode = require('jsonwebtoken');

const BOAT = "Boat";
const LOAD = "Load";
const USER = "User";

const router = express.Router();

const CLIENT_ID = 'ebhnD9Lje8C7QK2wd1hquV2bn6NWXi45';
const CLIENT_SECRET = 'P4Pgzs7Y1Znun16DxP1oX2aXYXDbQBCv5bZa9ApU8w2kzN3qZOyzACk6J121pTFe';
const DOMAIN = 'dev-jvatm0-a.auth0.com';

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine('handlebars', handlebars.engine);
app.set('view engine', 'handlebars');

/* ------------- Begin Utility Functions ------------- */
function fromDatastore(item){
    item.id = item[Datastore.KEY].id;
    return item;
}

const checkJwt = jwt({
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${DOMAIN}/.well-known/jwks.json`
    }),
  
    // Validate the audience and the issuer.
    issuer: `https://${DOMAIN}/`,
    algorithms: ['RS256']
  });

function getMgmtTokenOptions() {
    var mgmtTokenOptions = {
        method: 'POST',
        url: `https://${DOMAIN}/oauth/token`,
        headers: {'content-type': 'application/x-www-form-urlendcoded'},
        form: {
            grant_type: 'client_credentials',
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET,
            audience: `https://${DOMAIN}/api/v2/`
        }
    }
    return mgmtTokenOptions;
}

function getUserOptions(token) {
    var usersOptions = {
        method: 'GET',
        url: `https://${DOMAIN}/api/v2/users`,
        headers: {'content-type': 'application/json', Authorization: `Bearer ${token}`},
    };
    return usersOptions;
}

function getLoginOptions(email, password) {
    var loginOptions = { 
        method: 'POST',
        url: `https://${DOMAIN}/oauth/token`,
        headers: { 'content-type': 'application/json'},
        body: {
            grant_type: 'password',
            username: email,
            password: password,
            client_id: CLIENT_ID,
            client_secret: CLIENT_SECRET 
        },
        json: true
    };
    return loginOptions;
}

function getRegisterOptions(token, email, password) {
    var registerOptions = {
        method: 'POST',
        url: `https://${DOMAIN}/api/v2/users`,
        headers: {'content-type': 'application/json', Authorization: `Bearer ${token}`},
        json: {
            connection: 'Username-Password-Authentication',
            email: email,
            password: password
        }
    };
    return registerOptions;
}

function isValidLoadPostReq(req) {
    if (req.body.hasOwnProperty("weight") && 
        req.body.hasOwnProperty("content") && 
        req.body.hasOwnProperty("delivery_date")) {
            return true;
    }
    return false;        
}

function isValidLoadPatchReq(req) {
    if (req.body.hasOwnProperty("weight") || 
        req.body.hasOwnProperty("content") || 
        req.body.hasOwnProperty("delivery_date")) {
        return true;
    }
    return false;   
}

function getLoadPayload(req, id, weight, content, delivery_date, carrier) {
    var payload = {};
    payload.id = id;
    payload.weight = weight;
    payload.content = content;
    payload.delivery_date = delivery_date;
    payload.carrier = carrier;
    if (carrier != null) { payload.carrier.self = req.protocol + '://' + req.get('host') + req.baseUrl + '/boats/' + carrier.id;}
    payload.self = req.protocol + '://' + req.get('host') + req.baseUrl + '/loads/' + id;
    return payload;
}

function getPatchedLoad(req, load) {
    var new_load = {};
    new_load.weight = req.body.hasOwnProperty("weight") ? req.body.weight : load.weight;
    new_load.content = req.body.hasOwnProperty("content") ? req.body.content : load.content;
    new_load.delivery_date = req.body.hasOwnProperty("delivery_date") ? req.body.delivery_date : load.delivery_date;
    return new_load;
}

function isValidBoatPostReq(req) {
    if (req.body.hasOwnProperty("name") && 
        req.body.hasOwnProperty("type") && 
        req.body.hasOwnProperty("length")) {
        return true;
    }
    return false;     
}

function isValidBoatPatchReq(req) {
    if (req.body.hasOwnProperty("name") || 
        req.body.hasOwnProperty("type") || 
        req.body.hasOwnProperty("length")) {
        return true;
    }
    return false;   
}

function getBoatPayload(req, id, name, type, length, loads, owner) {
    var payload = {};
    payload.id = id;
    payload.name = name;
    payload.type = type;
    payload.length = length;
    payload.loads = [];
    if (loads.length > 0) {
        loads.forEach( (load) => {
            tempLoad = {};
            tempLoad.id = load
            tempLoad.self = req.protocol + '://' + req.get('host') + req.baseUrl + '/loads/' + load;
            payload.loads.push(tempLoad);
        });
    }
    payload.owner = owner;
    payload.self = req.protocol + '://' + req.get('host') + req.baseUrl + '/boats/' + id;
    return payload;
}

function getPatchedBoat(req, boat) {
    var new_boat = {};
    new_boat.name = req.body.hasOwnProperty("name") ? req.body.name : boat.name;
    new_boat.type = req.body.hasOwnProperty("type") ? req.body.type : boat.type;
    new_boat.length = req.body.hasOwnProperty("length") ? req.body.length : boat.length;
    return new_boat;
}

function isLoadAssignedToBoat(boat, loadId) {
    var isAssigned = false;
    boat.loads.forEach( (load) => {
        if(load.id == loadId) {
            isAssigned = true;
        }
    });
    return isAssigned;
}

/* ------------- End Utility Functions ------------- */

/* ------------- Begin User Model Functions ------------- */
function add_user(email, uniqueId) {
    var key = datastore.key(USER);
    const new_user = {"email": email, "uniqueId": uniqueId};
    return datastore.save({"key": key, "data": new_user}).then(() => {return key});
}

function get_users_unprotected() {
    const q = datastore.createQuery(USER);
    return datastore.runQuery(q).then( (entities) => {
        return entities[0].map(fromDatastore);
    });
}

/* ------------- End User Model Functions ------------- */

/* ------------- Begin Load Model Functions ------------- */
function post_load_unprotected(weight, content, delivery_date) {
    var key = datastore.key(LOAD);
	const new_load = {"weight": weight, "content": content, "delivery_date": delivery_date, "carrier": null};
	return datastore.save({"key":key, "data":new_load}).then(() => {return key});
}

function get_loads_unprotected(req) {
    var results = {};
    var pagQ = datastore.createQuery(LOAD).limit(5);
    var totalQ = datastore.createQuery(LOAD);
    return datastore.runQuery(totalQ).then( (totalEntities) => {
        results.total_items = totalEntities[0].length;
        if(Object.keys(req.query).includes("cursor")) {
            req.query.cursor = decodeURIComponent(req.query.cursor);
            pagQ = pagQ.start(req.query.cursor);
        }
        return datastore.runQuery(pagQ).then( (subEntities) => {
            results.items = [];
            subEntities[0].forEach( (entity) => {
                results.items.push(getLoadPayload(req, entity[Datastore.KEY].id, entity.weight, entity.content, entity.delivery_date, entity.carrier));
            });
            if(subEntities[1].moreResults !== Datastore.NO_MORE_RESULTS) {
                results.next = req.protocol + '://' + req.get('host') + req.baseUrl + '/loads/' + '?cursor=' + encodeURIComponent(subEntities[1].endCursor);
            }
            return results;
        });
    });
}

function get_a_load(req, id) {
    var result = null;
    var q = datastore.createQuery(LOAD);
    return datastore.runQuery(q).then( (entities) => {
        entities[0].forEach( (entity) => {
            if (entity[Datastore.KEY].id == id) {
                result = getLoadPayload(req, entity[Datastore.KEY].id, entity.weight, entity.content, entity.delivery_date, entity.carrier);
            }
        });
        return result;
    });
}

function put_a_load_unprotected(id, weight, content, delivery_date, carrier) {
    var key = datastore.key([LOAD, parseInt(id, 10)]);
    const updatedLoad = {"weight": weight, "content": content, "delivery_date": delivery_date, "carrier": carrier};
    return datastore.update({"key": key, "data": updatedLoad});
}

function patch_a_load_unprotected(id, weight, content, delivery_date, carrier) {
    var key = datastore.key([LOAD, parseInt(id, 10)]);
    const updatedLoad = {"weight": weight, "content": content, "delivery_date": delivery_date, "carrier": carrier};
    return datastore.update({"key": key, "data": updatedLoad});
}

function assign_carrier(id, weight, content, delivery_date, boatId, boatName) {
    const key = datastore.key([LOAD, parseInt(id, 10)]);
    const updatedLoad = {"weight": weight, "carrier": {"id": boatId, "name": boatName}, "content": content, "delivery_date": delivery_date};
    return datastore.update({"key": key, "data": updatedLoad});
}

function remove_carrier(id, weight, content, delivery_date) {
    const key = datastore.key([LOAD, parseInt(id, 10)]);
    const updatedLoad = {"weight": weight, "carrier": null, "content": content, "delivery_date": delivery_date};
    return datastore.update({"key": key, "data": updatedLoad});
}

function delete_load(id) {
    const key = datastore.key([LOAD, parseInt(id, 10)]);
    return datastore.delete(key);
}

/* ------------- End Load Model Functions ------------- */

/* ------------- Begin Boat Model Functions ------------- */
function post_boat(name, type, length, owner) {
    var key = datastore.key(BOAT);
	const new_boat = {"name": name, "type": type, "length": length, "loads": [], "owner": owner};
	return datastore.save({"key":key, "data":new_boat}).then(() => {return key});
}

function get_boats(req, owner) {
    var results = {};
    var pagQ = datastore.createQuery(BOAT).filter('owner', '=', owner).limit(5);
    var totalQ = datastore.createQuery(BOAT).filter('owner', '=', owner);
    return datastore.runQuery(totalQ).then( (totalEntities) => {
        results.total_items = totalEntities[0].length;
        if(Object.keys(req.query).includes("cursor")) {
            req.query.cursor = decodeURIComponent(req.query.cursor);
            pagQ = pagQ.start(req.query.cursor);
        }
        return datastore.runQuery(pagQ).then( (subEntities) => {
            results.items = [];
            subEntities[0].forEach( (entity) => {
                results.items.push(getBoatPayload(req, entity[Datastore.KEY].id, entity.name, entity.type, entity.length, entity.loads, entity.owner));
            });
            if(subEntities[1].moreResults !== Datastore.NO_MORE_RESULTS) {
                results.next = req.protocol + '://' + req.get('host') + req.baseUrl + '/boats/' + '?cursor=' + encodeURIComponent(subEntities[1].endCursor);
            }
            return results;
        });
    });
}

function get_a_boat(req, id) {
    var result = null;
    var q = datastore.createQuery(BOAT);
    return datastore.runQuery(q).then( (entities) => {
        entities[0].forEach( (entity) => {
            if (entity[Datastore.KEY].id == id) {
                result = getBoatPayload(req, entity[Datastore.KEY].id, entity.name, entity.type, entity.length, entity.loads, entity.owner);
            }
        });
        return result;
    });
}

function put_a_boat(id, name, type, length, loads, owner) {
    var key = datastore.key([BOAT, parseInt(id, 10)]);
    const updatedBoat = {"name": name, "type": type, "length": length, "loads": loads, "owner": owner};
    return datastore.update({"key": key, "data": updatedBoat});
}

function patch_a_boat(id, name, type, length, loads, owner) {
    var key = datastore.key([BOAT, parseInt(id, 10)]);
    const updatedBoat = {"name": name, "type": type, "length": length, "loads": loads, "owner": owner};
    return datastore.update({"key": key, "data": updatedBoat});
}

function assign_load(id, name, type, length, loads, owner, loadId) {
    loads.push(loadId);
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    const updatedBoat = {"name": name, "type": type, "length": length, "loads": loads, "owner": owner};
    return datastore.update({"key": key, "data": updatedBoat});
}

function remove_load(id, name, type, length, loads, owner, loadId) {
    const index = loads.indexOf(loadId);
    loads.splice(index, 1);
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    const updatedBoat = {"name": name, "type": type, "length": length, "loads": loads, "owner": owner};
    return datastore.update({"key": key, "data": updatedBoat});
}

function delete_boat(id) {
    const key = datastore.key([BOAT, parseInt(id, 10)]);
    return datastore.delete(key);
}

/* ------------- End Boat Model Functions ------------- */



/* ------------- Begin Controller Functions ------------- */

router.get('/', function(req, res) {
    res.render('login', {title: "Portfolio Assignment - Log In or Register"});
});

router.get('/users', function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    const users = get_users_unprotected().then( (users) => {
        res.status(200).send(users);
    });
});

router.get('/loads', function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_loads_unprotected(req).then( (results) => {
        res.status(200).send(results)
    });
});

router.post('/loads', function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    if (isValidLoadPostReq(req)) {
        post_load_unprotected(req.body.weight, req.body.content, req.body.delivery_date).then( (key) => {
            res.status(201).send(getLoadPayload(req, key.id, req.body.weight, req.body.content, req.body.delivery_date, null));
        });
    } else {
        res.status(400).send({"Error": "The request object is missing at least one of the required attributes"});
    }
});

router.get('/loads/:load_id', function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_a_load(req, req.params.load_id).then( (load) => {
        if (load == null) {
            res.status(404).send({"Error": "No load with this load_id exists"});
            return;
        }
        res.status(200).send(load);
    });
});

router.put('/loads/:load_id', function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_a_load(req, req.params.load_id).then( (load) => {
        if (load == null) {
            res.status(404).send({"Error": "No load with this load_id exists"});
            return;
        }
        if (isValidLoadPostReq(req)) {
            put_a_load_unprotected(load.id, req.body.weight, req.body.content, req.body.delivery_date, load.carrier).then( () => {
                res.status(201).send(getLoadPayload(req, load.id, req.body.weight, req.body.content, req.body.delivery_date, load.carrier));
            });
        } else {
            res.status(400).send({"Error": "The request object is missing at least one of the required attributes"});
        }
    });
});

router.patch('/loads/:load_id', function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_a_load(req, req.params.load_id).then( (load) => {
        if (load == null) {
            res.status(404).send({"Error": "No load with this load_id exists"});
            return;
        }
        if (isValidLoadPatchReq(req)) {
            var new_load = getPatchedLoad(req, load);
            patch_a_load_unprotected(load.id, new_load.weight, new_load.content, new_load.delivery_date, load.carrier).then( () => {
                res.status(200).send(getLoadPayload(req, load.id, new_load.weight, new_load.content, new_load.delivery_date, load.carrier));
            });
        } else {
            res.status(400).send({"Error": "The request object is missing at least one of the required attributes"});
        }
    });
});

router.delete('/loads/:load_id', function(req, res) {
    get_a_load(req, req.params.load_id).then( (load) => {
        if (load == null) {
            res.status(404).send({"Error": "No load with this load_id exists"});
            return;
        }
        if (load.carrier != null) {
            res.status(403).end();
            return;
        }
        delete_load(req.params.load_id).then( () => {
            res.status(204).send();
        });
    });
});

router.get('/boats', checkJwt, function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_boats(req, req.user.sub).then( (results) => {
        res.status(200).send(results);
    });
});

router.post('/boats', checkJwt, function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    if (isValidBoatPostReq(req)) {
        post_boat(req.body.name, req.body.type, req.body.length, req.user.sub).then( (key) => {
            res.status(201).send(getBoatPayload(req, key.id, req.body.name, req.body.type, req.body.length, [], req.user.sub));
        });
    } else {
        res.status(400).send({"Error": "The request object is missing at least one of the required attributes"});
    }
});

router.get('/boats/:boat_id', checkJwt, function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_a_boat(req, req.params.boat_id).then( (boat) => {
        if (boat == null) {
            res.status(404).send({"Error": "No boat with this boat_id exists"});
            return;
        }
        if (boat.owner != req.user.sub) {
            res.status(403).end();
            return;
        } 
        res.status(200).send(boat);
    });
});

router.put('/boats/:boat_id', checkJwt, function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_a_boat(req, req.params.boat_id).then( (boat) => {
        if (boat == null) {
            res.status(404).send({"Error": "No boat with this boat_id exists"});
            return;
        }
        if (boat.owner != req.user.sub) {
            res.status(403).end();
            return;
        } 
        if (isValidBoatPostReq(req)) {
            put_a_boat(boat.id, req.body.name, req.body.type, req.body.length, boat.loads, boat.owner).then( () => {
                res.status(201).send(getBoatPayload(req, boat.id, req.body.name, req.body.type, req.body.length, boat.loads, boat.owner));
            });
        } else {
            res.status(400).send({"Error": "The request object is missing at least one of the required attributes"});
        }
    });
});

router.delete('/boats/:boat_id', checkJwt, function(req, res) {
    get_a_boat(req, req.params.boat_id).then( (boat) => {
        if (boat == null) {
            res.status(404).send({"Error": "No boat with this boat_id exists"});
            return;
        }
        if (boat.owner != req.user.sub) {
            res.status(403).end();
            return;
        }
        if (boat.loads.length != 0) {
            res.status(403).end();
            return;
        }
        delete_boat(req.params.boat_id).then( () => {
            res.status(204).send();
        });
    });
});

router.patch('/boats/:boat_id', checkJwt, function(req, res) {
    if (!req.accepts('application/json')) {
        res.status(406).end();
        return;
    }
    get_a_boat(req, req.params.boat_id).then( (boat) => {
        if (boat == null) {
            res.status(404).send({"Error": "No boat with this boat_id exists"});
            return;
        }
        if (boat.owner != req.user.sub) {
            res.status(403).end();
            return;
        } 
        if (isValidBoatPatchReq(req)) {
            var new_boat = getPatchedBoat(req, boat);
            patch_a_boat(boat.id, new_boat.name, new_boat.type, new_boat.length, boat.loads, boat.owner).then( () => {
                res.status(200).send(getBoatPayload(req, boat.id, new_boat.name, new_boat.type, new_boat.length, boat.loads, boat.owner));
            });
        } else {
            res.status(400).send({"Error": "The request object is missing at least one of the required attributes"});
        }
    });
});

router.put('/boats/:boat_id/loads/:load_id', checkJwt, function(req, res) {
    get_a_boat(req, req.params.boat_id).then( (boat) => {
        get_a_load(req, req.params.load_id).then( (load) => {
            if (boat == null || load == null) {
                res.status(404).end();
                return;
            }
            if (boat.owner != req.user.sub) {
                res.status(403).end();
                return;
            } 
            if (load.carrier != null) {
                res.status(403).end();
                return;
            }
            assign_load(boat.id, boat.name, boat.type, boat.length, boat.loads, boat.owner, load.id).then( () => {
                assign_carrier(load.id, load.weight, load.content, load.delivery_date, boat.id, boat.name).then( () => {
                    res.status(204).end();
                });
            });
        });
    });
});

router.delete('/boats/:boat_id/loads/:load_id', checkJwt, function(req, res) {
    get_a_boat(req, req.params.boat_id).then( (boat) => {
        get_a_load(req, req.params.load_id).then( (load) => {
            if (boat == null || load == null) {
                res.status(404).end();
                return;
            }
            if (boat.owner != req.user.sub) {
                res.status(403).end();
                return;
            } 
            if (!isLoadAssignedToBoat(boat, load.id)) {
                res.status(403).end();
                return;
            }
            remove_load(boat.id, boat.name, boat.type, boat.length, boat.loads, boat.owner, load.id).then( () => {
                remove_carrier(load.id, load.weight, load.content, load.delivery_date).then( () => {
                    res.status(204).end();
                });
            });
        });
    });
});

router.post('/login', function(req, res) { 
    var userExists = false;
    var token;
    request(getMgmtTokenOptions(), function(error, response, body) {
        token = JSON.parse(body).access_token;
        request(getUserOptions(token), function(error, response, body) {
            JSON.parse(body).forEach( (user) => {
                if (user.email == req.body.email) { userExists = true; }
            });
            if (userExists) {
                request(getLoginOptions(req.body.email, req.body.password), function(error, response, body) {
                    if (body.id_token){
                        res.render('user_info', {title: 'User Info', jwt: body.id_token, sub: jwtDecode.decode(body.id_token).sub});
                    } else {
                        res.render('login_invalid_credentials', {title: 'Portfolio Assignment - Log In or Register'});
                    }
                });
            } else {
                res.render('login_invalid_credentials', {title: 'Portfolio Assignment - Log In or Register'});
            }
        });
    });
});

router.post('/register', function(req, res) {
    var userExists = false;
    var token;
    request(getMgmtTokenOptions(), function(error, response, body) {
        token = JSON.parse(body).access_token;
        request(getUserOptions(token), function(error, response, body) {
            JSON.parse(body).forEach( (user) => {
                if (user.email == req.body.email) { userExists = true; }
            });
            if (!userExists) {
                request(getRegisterOptions(token, req.body.email, req.body.password), function(error, response, body) {
                    request(getLoginOptions(req.body.email, req.body.password), function(error, response, body) {
                        add_user(req.body.email, jwtDecode.decode(body.id_token).sub);
                        res.render('user_info', {title: 'User Info', jwt: body.id_token, sub: jwtDecode.decode(body.id_token).sub});
                    });
                });
            } else {
                res.render('login_invalid_credentials', {title: 'Portfolio Assignment - Log In or Register'});
            }
        });
    });
});

router.delete('/loads', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

router.delete('/boats', function (req, res){
    res.set('Accept', 'POST');
    res.status(405).end();
});

/* ------------- End Controller Functions ------------- */

app.use('/', router);
app.use((err, req, res, next) => {
    if (err.name === 'UnauthorizedError') { res.status(401).end(); }
});

// Listen to the App Engine-specified port, or 8080 otherwise
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}...`);
});