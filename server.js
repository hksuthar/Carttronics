var express = require('express');
var app=express();

/* Harsh 07-10-2016 */

var qs = require('querystring');
var async = require('async');
var bcrypt = require('bcryptjs');
var bodyParser = require('body-parser');
var colors = require('colors');
var cors = require( 'cors');
var logger = require('morgan');
var jwt = require('jwt-simple');
var moment = require('moment');
var request = require('request');
var mongoose = require('mongoose');
var config = require('./config');

var userSchema = new mongoose.Schema({
  email: { type: String, unique: true, lowercase: true },
  password: { type: String, select: false },
  displayName: String,
  picture: String,
  bitbucket: String,
  facebook: String,
  foursquare: String,
  google: String,
  github: String,
  instagram: String,
  linkedin: String,
  live: String,
  yahoo: String,
  twitter: String,
  twitch: String,
  spotify: String
});

userSchema.pre('save', function(next) {
  var user = this;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(10, function(err, salt) {
    bcrypt.hash(user.password, salt, function(err, hash) {
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(password, done) {
  bcrypt.compare(password, this.password, function(err, isMatch) {
    done(err, isMatch);
  });
};


var User = mongoose.model('User', userSchema);

mongoose.connect(config.MONGO_URI);
mongoose.connection.on('error', function(err) {
  console.log('Error: Could not connect to MongoDB. Did you forget to run `mongod`?'.red);
});

app.use(cors());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

/*
 |--------------------------------------------------------------------------
 | Login Required Middleware
 |--------------------------------------------------------------------------
 */
function ensureAuthenticated(req, res, next) {
  if (!req.header('Authorization')) {
    return res.status(401).send({ message: 'Please make sure your request has an Authorization header' });
  }
  var token = req.header('Authorization').split(' ')[1];

  var payload = null;
  try {
    payload = jwt.decode(token, config.TOKEN_SECRET);
  }
  catch (err) {
    return res.status(401).send({ message: err.message });
  }

  if (payload.exp <= moment().unix()) {
    return res.status(401).send({ message: 'Token has expired' });
  }
  req.user = payload.sub;
  next();
}

/*
 |--------------------------------------------------------------------------
 | Generate JSON Web Token
 |--------------------------------------------------------------------------
 */
function createJWT(user) {
  var payload = {
    sub: user._id,
    iat: moment().unix(),
    exp: moment().add(14, 'days').unix()
  };
  return jwt.encode(payload, config.TOKEN_SECRET);
}

/*
 |--------------------------------------------------------------------------
 | GET /api/me
 |--------------------------------------------------------------------------
 */
app.get('/api/me', ensureAuthenticated, function(req, res) {
  User.findById(req.user, function(err, user) {
    res.send(user);
  });
});

/*
 |--------------------------------------------------------------------------
 | PUT /api/me
 |--------------------------------------------------------------------------
 */
app.put('/api/me', ensureAuthenticated, function(req, res) {
  User.findById(req.user, function(err, user) {
    if (!user) {
      return res.status(400).send({ message: 'User not found' });
    }
    user.displayName = req.body.displayName || user.displayName;
    user.email = req.body.email || user.email;
    user.save(function(err) {
      res.status(200).end();
    });
  });
});


/*
 |--------------------------------------------------------------------------
 | Log in with Email
 |--------------------------------------------------------------------------
 */
app.post('/auth/login', function(req, res) {
  User.findOne({ email: req.body.email }, '+password', function(err, user) {
    if (!user) {
      return res.status(401).send({ message: 'Invalid email and/or password' });
    }
    user.comparePassword(req.body.password, function(err, isMatch) {
      if (!isMatch) {
        return res.status(401).send({ message: 'Invalid email and/or password' });
      }
      res.send({ token: createJWT(user) });
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Create Email and Password Account
 |--------------------------------------------------------------------------
 */
app.post('/auth/signup', function(req, res) {
  User.findOne({ email: req.body.email }, function(err, existingUser) {
    if (existingUser) {
      return res.status(409).send({ message: 'Email is already taken' });
    }
    var user = new User({
      displayName: req.body.displayName,
      email: req.body.email,
      password: req.body.password
    });
    user.save(function(err, result) {
      if (err) {
        res.status(500).send({ message: err.message });
      }
      res.send({ token: createJWT(result) });
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Login with Google
 |--------------------------------------------------------------------------
 */
app.post('/auth/google', function(req, res) {
  var accessTokenUrl = 'https://accounts.google.com/o/oauth2/token';
  var peopleApiUrl = 'https://www.googleapis.com/plus/v1/people/me/openIdConnect';
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.GOOGLE_SECRET,
    redirect_uri: req.body.redirectUri,
    grant_type: 'authorization_code'
  };

  // Step 1. Exchange authorization code for access token.
  request.post(accessTokenUrl, { json: true, form: params }, function(err, response, token) {
    var accessToken = token.access_token;
    var headers = { Authorization: 'Bearer ' + accessToken };

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: peopleApiUrl, headers: headers, json: true }, function(err, response, profile) {
      if (profile.error) {
        return res.status(500).send({message: profile.error.message});
      }
      // Step 3a. Link user accounts.
      if (req.header('Authorization')) {
        User.findOne({ google: profile.sub }, function(err, existingUser) {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a Google account that belongs to you' });
          }
          var token = req.header('Authorization').split(' ')[1];
          var payload = jwt.decode(token, config.TOKEN_SECRET);
          User.findById(payload.sub, function(err, user) {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.google = profile.sub;
            user.picture = user.picture || profile.picture.replace('sz=50', 'sz=200');
            user.displayName = user.displayName || profile.name;
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3b. Create a new user account or return an existing one.
        User.findOne({ google: profile.sub }, function(err, existingUser) {
          if (existingUser) {
            return res.send({ token: createJWT(existingUser) });
          }
          var user = new User();
          user.google = profile.sub;
          user.picture = profile.picture.replace('sz=50', 'sz=200');
          user.displayName = profile.name;
          user.save(function(err) {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Login with GitHub
 |--------------------------------------------------------------------------
 */
app.post('/auth/github', function(req, res) {
  var accessTokenUrl = 'https://github.com/login/oauth/access_token';
  var userApiUrl = 'https://api.github.com/user';
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.GITHUB_SECRET,
    redirect_uri: req.body.redirectUri
  };

  // Step 1. Exchange authorization code for access token.
  request.get({ url: accessTokenUrl, qs: params }, function(err, response, accessToken) {
    accessToken = qs.parse(accessToken);
    var headers = { 'User-Agent': 'Satellizer' };

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: userApiUrl, qs: accessToken, headers: headers, json: true }, function(err, response, profile) {

      // Step 3a. Link user accounts.
      if (req.header('Authorization')) {
        User.findOne({ github: profile.id }, function(err, existingUser) {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a GitHub account that belongs to you' });
          }
          var token = req.header('Authorization').split(' ')[1];
          var payload = jwt.decode(token, config.TOKEN_SECRET);
          User.findById(payload.sub, function(err, user) {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.github = profile.id;
            user.picture = user.picture || profile.avatar_url;
            user.displayName = user.displayName || profile.name;
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3b. Create a new user account or return an existing one.
        User.findOne({ github: profile.id }, function(err, existingUser) {
          if (existingUser) {
            var token = createJWT(existingUser);
            return res.send({ token: token });
          }
          var user = new User();
          user.github = profile.id;
          user.picture = profile.avatar_url;
          user.displayName = profile.name;
          user.email = profile.email;

          user.save(function() {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
});

/*
|--------------------------------------------------------------------------
| Login with Instagram
|--------------------------------------------------------------------------
*/
app.post('/auth/instagram', function(req, res) {
  var accessTokenUrl = 'https://api.instagram.com/oauth/access_token';

  var params = {
    client_id: req.body.clientId,
    redirect_uri: req.body.redirectUri,
    client_secret: config.INSTAGRAM_SECRET,
    code: req.body.code,
    grant_type: 'authorization_code'
  };

  // Step 1. Exchange authorization code for access token.
  request.post({ url: accessTokenUrl, form: params, json: true }, function(error, response, body) {

    // Step 2a. Link user accounts.
    if (req.header('Authorization')) {
      User.findOne({ instagram: body.user.id }, function(err, existingUser) {
        if (existingUser) {
          return res.status(409).send({ message: 'There is already an Instagram account that belongs to you' });
        }

        var token = req.header('Authorization').split(' ')[1];
        var payload = jwt.decode(token, config.TOKEN_SECRET);

        User.findById(payload.sub, function(err, user) {
          if (!user) {
            return res.status(400).send({ message: 'User not found' });
          }
          user.instagram = body.user.id;
          user.picture = user.picture || body.user.profile_picture;
          user.displayName = user.displayName || body.user.username;
          user.save(function() {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      });
    } else {
      // Step 2b. Create a new user account or return an existing one.
      User.findOne({ instagram: body.user.id }, function(err, existingUser) {
        if (existingUser) {
          return res.send({ token: createJWT(existingUser) });
        }

        var user = new User({
          instagram: body.user.id,
          picture: body.user.profile_picture,
          displayName: body.user.username
        });

        user.save(function() {
          var token = createJWT(user);
          res.send({ token: token, user: user });
        });
      });
    }
  });
});

/*
 |--------------------------------------------------------------------------
 | Login with LinkedIn
 |--------------------------------------------------------------------------
 */
app.post('/auth/linkedin', function(req, res) {
  var accessTokenUrl = 'https://www.linkedin.com/uas/oauth2/accessToken';
  var peopleApiUrl = 'https://api.linkedin.com/v1/people/~:(id,first-name,last-name,email-address,picture-url)';
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.LINKEDIN_SECRET,
    redirect_uri: req.body.redirectUri,
    grant_type: 'authorization_code'
  };

  // Step 1. Exchange authorization code for access token.
  request.post(accessTokenUrl, { form: params, json: true }, function(err, response, body) {
    if (response.statusCode !== 200) {
      return res.status(response.statusCode).send({ message: body.error_description });
    }
    var params = {
      oauth2_access_token: body.access_token,
      format: 'json'
    };

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: peopleApiUrl, qs: params, json: true }, function(err, response, profile) {

      // Step 3a. Link user accounts.
      if (req.header('Authorization')) {
        User.findOne({ linkedin: profile.id }, function(err, existingUser) {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a LinkedIn account that belongs to you' });
          }
          var token = req.header('Authorization').split(' ')[1];
          var payload = jwt.decode(token, config.TOKEN_SECRET);
          User.findById(payload.sub, function(err, user) {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.linkedin = profile.id;
            user.picture = user.picture || profile.pictureUrl;
            user.displayName = user.displayName || profile.firstName + ' ' + profile.lastName;
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3b. Create a new user account or return an existing one.
        User.findOne({ linkedin: profile.id }, function(err, existingUser) {
          if (existingUser) {
            return res.send({ token: createJWT(existingUser) });
          }
          var user = new User();
          user.linkedin = profile.id;
          user.picture = profile.pictureUrl;
          user.displayName = profile.firstName + ' ' + profile.lastName;
          user.save(function() {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
});

/*
 |--------------------------------------------------------------------------
 | Login with Windows Live
 |--------------------------------------------------------------------------
 */
app.post('/auth/live', function(req, res) {
  async.waterfall([
    // Step 1. Exchange authorization code for access token.
    function(done) {
      var accessTokenUrl = 'https://login.live.com/oauth20_token.srf';
      var params = {
        code: req.body.code,
        client_id: req.body.clientId,
        client_secret: config.WINDOWS_LIVE_SECRET,
        redirect_uri: req.body.redirectUri,
        grant_type: 'authorization_code'
      };
      request.post(accessTokenUrl, { form: params, json: true }, function(err, response, accessToken) {
        done(null, accessToken);
      });
    },
    // Step 2. Retrieve profile information about the current user.
    function(accessToken, done) {
      var profileUrl = 'https://apis.live.net/v5.0/me?access_token=' + accessToken.access_token;
      request.get({ url: profileUrl, json: true }, function(err, response, profile) {
        done(err, profile);
      });
    },
    function(profile) {
      // Step 3a. Link user accounts.
      if (req.header('Authorization')) {
        User.findOne({ live: profile.id }, function(err, user) {
          if (user) {
            return res.status(409).send({ message: 'There is already a Windows Live account that belongs to you' });
          }
          var token = req.header('Authorization').split(' ')[1];
          var payload = jwt.decode(token, config.TOKEN_SECRET);
          User.findById(payload.sub, function(err, existingUser) {
            if (!existingUser) {
              return res.status(400).send({ message: 'User not found' });
            }
            existingUser.live = profile.id;
            existingUser.displayName = existingUser.displayName || profile.name;
            existingUser.save(function() {
              var token = createJWT(existingUser);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3b. Create a new user or return an existing account.
        User.findOne({ live: profile.id }, function(err, user) {
          if (user) {
            return res.send({ token: createJWT(user) });
          }
          var newUser = new User();
          newUser.live = profile.id;
          newUser.displayName = profile.name;
          newUser.save(function() {
            var token = createJWT(newUser);
            res.send({ token: token });
          });
        });
      }
    }
  ]);
});

/*
 |--------------------------------------------------------------------------
 | Login with Facebook
 |--------------------------------------------------------------------------
 */
app.post('/auth/facebook', function(req, res) {
  var fields = ['id', 'email', 'first_name', 'last_name', 'link', 'name'];
  var accessTokenUrl = 'https://graph.facebook.com/v2.5/oauth/access_token';
  var graphApiUrl = 'https://graph.facebook.com/v2.5/me?fields=' + fields.join(',');
  var params = {
    code: req.body.code,
    client_id: req.body.clientId,
    client_secret: config.FACEBOOK_SECRET,
    redirect_uri: req.body.redirectUri
  };

  // Step 1. Exchange authorization code for access token.
  request.get({ url: accessTokenUrl, qs: params, json: true }, function(err, response, accessToken) {
    if (response.statusCode !== 200) {
      return res.status(500).send({ message: accessToken.error.message });
    }

    // Step 2. Retrieve profile information about the current user.
    request.get({ url: graphApiUrl, qs: accessToken, json: true }, function(err, response, profile) {
      if (response.statusCode !== 200) {
        return res.status(500).send({ message: profile.error.message });
      }
      if (req.header('Authorization')) {
        User.findOne({ facebook: profile.id }, function(err, existingUser) {
          if (existingUser) {
            return res.status(409).send({ message: 'There is already a Facebook account that belongs to you' });
          }
          var token = req.header('Authorization').split(' ')[1];
          var payload = jwt.decode(token, config.TOKEN_SECRET);
          User.findById(payload.sub, function(err, user) {
            if (!user) {
              return res.status(400).send({ message: 'User not found' });
            }
            user.facebook = profile.id;
            user.picture = user.picture || 'https://graph.facebook.com/v2.3/' + profile.id + '/picture?type=large';
            user.displayName = user.displayName || profile.name;
            user.save(function() {
              var token = createJWT(user);
              res.send({ token: token });
            });
          });
        });
      } else {
        // Step 3. Create a new user account or return an existing one.
        User.findOne({ facebook: profile.id }, function(err, existingUser) {
          if (existingUser) {
            var token = createJWT(existingUser);
            return res.send({ token: token });
          }
          var user = new User();
          user.facebook = profile.id;
          user.picture = 'https://graph.facebook.com/' + profile.id + '/picture?type=large';
          user.displayName = profile.name;
          user.save(function() {
            var token = createJWT(user);
            res.send({ token: token });
          });
        });
      }
    });
  });
});



/**********************/

var csvjson = require('csvjson');
var parse = require('csv-parse');
var mongojs=require('mongojs');

var mongoose = require('mongoose');
var csv = require('fast-csv');
var path = require('path');

var MongoClient = require('mongodb').MongoClient;
var db = null;
var dbName='carttronics'
/*var dbName_user = 'user'
var url = 'mongodb://localhost:27017/' + dbName_user*/
var dbName_user = 'user'
var url = 'mongodb://localhost:27017/' + dbName_user
var url_carttronics = 'mongodb://localhost:27017/'+dbName

var fs = require('fs');
var bodyParser = require('body-parser');
var multer = require('multer');
var moment = require('moment'); 
var collection;
var str = "";
var aData = null;
var Document = null;

/******************************** For File uploaded Start ************************************/

app.use(express.static('../Carttronics_Graph/Client/', { index: 'login.html' }));

app.use(bodyParser.json());

app.get('/', function (req, res) {
    res.status(200).sendFile('index.html', { root: path.join(__dirname, '../Carttronics_Graph/Client/') });
});

app.get('/carttronicslogin',function(req, res){
    console.log("I see a get request")
});

app.get('/Chart_1', function (req, res) {
    console.log("I see a get request from Chart_1")
    MongoClient.connect(url_carttronics, function (err, db) {
        if (err) {
            console.log('Unable to connect to the mongoDB server. Error:', err);
        } else {
            console.log('Connection Done ', url_carttronics);
            db.listCollections().toArray(function(err, collInfos) {
                // collInfos is an array of collection info objects that look like:
                // { name: 'test', options: {} }
                console.log(collInfos);
                //res.send(collInfos);
            });
            
            var collection = db.collection('carttronics');
            var adata = []

            collection.find({}).toArray( function (err, docs) { // Should succeed
                if (err)
                    throw err;
                else {
                    res.send(docs);
                }
            });
        }     
    });
});

app.post('/carttronicslogin', function(req,res){
    
    console.log("i am Harsh Patel");

    console.log(req.body.email);

    //Main Data insert
    MongoClient.connect(url, function (err, db) {
        if (err) {
            console.log('Unable to connect to the mongoDB server. Error:', err);
        } else {
            console.log('Connection Done ', url);
            //console.log(db);
            var collection = db.collection('user');
            //console.log(collection.find );
            var data = collection.find({ 'email': req.body.email, "password": req.body.pass });
            
            collection.find({ 'email': req.body.email, "password": req.body.pass }, function (errr, docs) { // Should succeed
                if (errr)
                    console.log("Please enter valid email and password");
                   //res.send("not");
                else {                
                    docs.each(function (err, doc) {
                        if (doc) {
                            console.log(doc.username);
                            res.send("index.html");
                        }    
                    });
                }
            });
        }
    });
});

app.post('/Chart_1', function (req, res) {
    
    console.log("i see post request from Chart_1")
    
    //Main Data insert
    MongoClient.connect(url_carttronics, function (err, db) {
        if (err) {
            console.log('Unable to connect to the mongoDB server. Error:', err);
        } else {
            console.log('Connection Done ', url_carttronics);
            //console.log(db);
            var collection = db.collection('user');
            collection.find({ 'email': req.body.email, "password": req.body.pass }, function (err, docs) { // Should succeed
                if (err)
                    res.send("not Ok");
                else {
                    docs.each(function (err, doc) {
                        if (doc) {
                            console.log(doc.email)
                            res.send("index.html");
                            //res.status(200).sendFile('Chart.html', { root: path.join(__dirname, '../carttronics/client/') });//res.sendFile(__dirname + '/Client/index.html');
                                                        
                        }
                    });
                }
            });   
        }
        //var db = 'CartData';
    });
});

    /************* Added by Hemesh from Krutika Ends **********************/

    app.use(function(req, res, next) { //allow cross origin requests
        res.setHeader("Access-Control-Allow-Methods", "POST, PUT, OPTIONS, DELETE, GET");
        res.header("Access-Control-Allow-Origin", "http://localhost");
        res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
        next();
    });

    var storage = multer.diskStorage({ //multers disk storage settings
        destination: function (req, file, cb) {
            cb(null, './uploads/');
        },
        filename: function (req, file, cb) {
            var datetimestamp = Date.now();
            cb(null, file.fieldname + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length -1]);
        }
    });

    var upload = multer({ //multer settings
        storage: storage
   }).single('file');

    app.post('/upload', function (req, res) {

        upload(req, res, function (err) {
            if(err){
                 res.json({error_code:1,err_desc:err});
                 return;
            }

            
            /***************************** Main Data Base all the data store in carttronics collection (Start)  **********************************/

            console.log("It is done");
            res.json({ error_code: 0, err_desc: null });
            var filename = '/' + req.file.path;
            console.log(filename.length);
            console.log(filename);
           
            var Converter = require("csvtojson").Converter;

            var updatefilename = "./Updatecsvfile.csv";
            console.log(updatefilename.length);
                 
            fs.readFileSync(__dirname+filename).toString().split(' ').forEach(function (line) {
                fs.appendFileSync(updatefilename, line.toString());
            });
                var Converter = require("csvtojson").Converter;
                console.log(updatefilename);
                var fileStream = fs.createReadStream(__dirname+updatefilename.substring(1,19));
                var converter = new Converter({ constructResult: true });
                
                converter.on("end_parsed", function (jsonObj) {
                    console.log(jsonObj);
                    var jsonfile = require('jsonfile');
                    var file_json =__dirname+ "/uploads/"+updatefilename.substring(1,16 )+'json';
                    jsonfile.writeFile(file_json, jsonObj, function (err) { console.error(err); });
                });
                fileStream.pipe(converter);
            
            //Logic implimentation for the separate files starts
            var filename = "/uploads/Updatecsvfile.json" 
            var people = [], casters = {}, dts = [], dts1 = [];
            var fileContents = fs.readFileSync(__dirname + filename);
            var ss = fileContents.toString().split('\n');
            //console.log(ss);
            for (var i = 1; i < ss.length-1; i++) {
                var s = ss[i].toString().split(',');
                var dt = '', t = '', sn = '', m = '';
                if (s[2] != undefined)
                    dt = s[2].replace("\"", "");

                if (dts.indexOf(dt) < 0) {
                    dts.push(dt);
                }

                if (s[0] != undefined)
                    t = s[0].replace("\"", "").replace("PT", "");
                var d = moment(t).format("YYYY-MM-DD hh:mm");
                
                var temp = d + 621355968000000000;
                if (dts1.indexOf(d) < 0) {
                    dts1.push(d);
                }
                
                if (s[1] != undefined)
                    sn = s[1].replace("\"", "");

                if (!casters.hasOwnProperty(sn)) {
                    var c = {
                        locs: [],
                        type: "NA",
                    }
                    // var obj = {};
                    casters[sn] = c;
                    //casters.push(obj);
                }
                var l = {};

                if (s[3] != undefined)
                    m = s[3].replace("\"", "");

                if (m.match(/Enter Store/gi)) { l["location"] = "S"; }
                else if (m.match(/Must Check/gi)) { l["location"] = "S"; }
                else if (m.match(/Check/gi)) { l["location"] = "C"; }
                else if (m.match(/Leave Store/gi)) { l["location"] = "P"; }
                else if (m.match(/Trolley Bay Outside/gi)) { l["location"] = "T"; }
                else if (m.match(/Trolley Bay Outside/gi)) { l["location"] = "T"; }
                else if (m.match(/Perimeter Lock/gi)) {
                    l["location"] = "L";
                    if (casters[sn].locs.length != 0)
                        if (casters[sn].locs[casters[sn].locs.length - 1].location == "L")
                            l["location"] = "P";
                }
                else if (m.match(/Unlock/gi)) { l["location"] = "P"; }
                if (l["location"] != "M" && sn != undefined) {
                    l["when"] = moment(t);
                    //l["when"] = d;
                    if (casters[sn] != undefined && casters[sn].locs.length == 0) { casters[sn].locs.push(l); }
                    else if (casters[sn] != undefined) {
                        // console.log(casters[sn]);
                        var last = casters[sn].locs[casters[sn].locs.length - 1];
                        if (last["when"] == d)
                            casters[sn].locs[casters[sn].locs.length - 1] = l;
                        else
                            casters[sn].locs.push(l);
                    }
                }
            }
            var dd = dts1.sort();
            var start = moment(dd[0]);
            var end = moment(dd[dd.length - 1]);

            for (var k in casters) {
                var s = casters[k];
                var ct = start;
                var tlocs = [];
                var thisLoc = {};
                thisLoc["location"] = "M";
                thisLoc["when"] = start;
                for (var li = 0; li < s.locs.length; li++) {
                    var breaker = 0;
                    while (ct._i < s.locs[li].when._i) {
                        breaker++;
                        tlocs.push(thisLoc);
                        ct = moment("" + moment(ct.toDate().getTime() + 60*1000).format("YYYY-MM-DD hh:mm:ss.SSSS"));//moment(ct).add(1, 'm');// check conversion
                    }
                }
                var breaker = 0;
                while (ct._i < end._i) {
                    breaker++;
                    tlocs.push(thisLoc);
                    ct = moment("" + moment(ct.toDate().getTime() + 60*1000).format("YYYY-MM-DD hh:mm:ss.SSSS"));// check conversion YYYY-MM-DD hh:mm:ss.SSSS
                }

                s['slocs'] = tlocs;
                s['locs'] = null;
                casters[k] = s;
            }
            var output = [];
            var output2 = [];
            output.push("Date,Missing,Parking Lot,Trolley Bay,Shopping,Checked Out");
            output2.push("Date,Stops");

            var outputMy = "";
            var output2My = "";
            outputMy = "Date,Missing,Parking Lot,Trolley Bay,Shopping,Checked Out";
            output2My = "Date,Stops";

            var lck = 0;
            var ct = start;
            
            var aa = moment(ct).add(10, 'm')
            var breaker = 0;

            for (var ct = start ; ct._i < end._i; ct = moment("" + moment(ct.toDate().getTime() + 60 * 1000).format("YYYY-MM-DD hh:mm:ss.SSSS"))) {
                breaker++;
                var m = 0; var s = 0; var c = 0; var p = 0; var t = 0;
                var xi;

                for (var sss in casters) {
                    try {
                            if (casters[sss].slocs[xi] == "S") s += 1;
                            if (casters[sss].slocs[xi] == "M") m += 1;
                            if (casters[sss].slocs[xi] == "C") c += 1;
                            if (casters[sss].slocs[xi] == "P") p += 1;
                            if (casters[sss].slocs[xi] == "T") t += 1;
                            if (casters[sss].slocs[xi] == "L")
                            if (xi == 0) lck += 1;
                                else if (casters[sss].slocs[xi - 1] != "L")
                                    lck += 1;
                        }
                        catch (ex) {
                            console.log("Error is coming in printing");
                        }
                }
                var ts = ct - new Date(1970, 1, 1);
                var xss = "" + ts + "," + m + "," + p + "," + t + "," + s + "," + c;
                outputMy = outputMy + "\n" + xss;
                output.push(xss);
                
                var xss1 = "" + ts + "," + lck;
                output2My = output2My + "\n" + xss1;
                output2.push(xss1);
                xi += 1;
            }
            console.log(output);
            var xfilename = __dirname + filename.substring(0, 27)+'_x'+'.csv';
            var stopfilename = __dirname + filename.substring(0, 27) + '_stops' + '.csv';
            fs.writeFile(xfilename, outputMy);
            fs.writeFile(stopfilename, output2My);

            //Logic implimentation for the separate files Ends

            var fileStream = new fs.createReadStream(__dirname + filename);
            console.log(fileStream);
            console.log("It is done 2");
            var csvconverter = new Converter({ constructResult: true });
            console.log("It is done 3");
            
            //converts the file in to jason

            //end_parsed or record_parsed
            csvconverter.on("end_parsed", function (jsonObj) {
                console.log(jsonObj);
                console.log("in json funtion");
                var jsonfile = require('jsonfile');

                var file_json = __dirname + filename.substring(0, 28) + 'json';
                console.log('Harsh File');
                console.log(file_json);
                jsonfile.writeFile(file_json, jsonObj, function (err) { console.error(err); });
                
                MongoClient.connect(url_carttronics, function (err, db) {
                    if (err) {
                        console.log('Unable to connect to the mongoDB server. Error:', err);
                    } else {
                        console.log('Connection Done ', url_carttronics);
                        var mydocuments = fs.readFile(file_json, 'utf8', function (err, data) {
                            var collection = db.collection('carttronics');
                            console.log(collection);
                            collection.insert(JSON.parse(data), function (err, docs) { // Should succeed
                                collection.count(function (err, count) {
                                    console.log("done");
                                    db.close();
                                });
                            });
                        });
                    }
                });
            });
            fileStream.pipe(csvconverter);

            /***************************** Main Data Base all the data store in carttronics collection (End)  **********************************/
            


            /***************************** Graph ploat database in particular store wise (Start)  **********************************/

            var filename = '/' + req.file.path;
            var updatefilename = "./Updatecsvfile.csv";
            console.log(updatefilename.length);
                 
            fs.readFileSync(__dirname+filename).toString().split(' ').forEach(function (line) {
                fs.appendFileSync(updatefilename, line.toString());
            });
                var Converter = require("csvtojson").Converter;
                var fileStream = fs.createReadStream(__dirname+updatefilename.substring(1,19));
                var converter = new Converter({ constructResult: true });
                
                converter.on("end_parsed", function (jsonObj) {
                    
                    var jsonfile = require('jsonfile');
                    var file_json =__dirname+ "/uploads/"+updatefilename.substring(1,16 )+'json';
                    jsonfile.writeFile(file_json, jsonObj, function (err) { console.error(err); });
                    fs.unlink(__dirname+filename, function (err) {
                        if (err) {
                            return console.error(err);
                        }
                    console.log("File deleted successfully!");
                    });
                    fs.unlink(__dirname + updatefilename.substring(1,19), function (err) {
                       if (err) {
                           return console.error(err);
                       }
                    console.log("File deleted successfully updatecsv!");
                    });
                    
                    mongoose.connect('mongodb://localhost/carttronics');
                    var db = mongoose.connection;
                
                    db.on('error', console.error.bind(console, 'Connection error:'));

                    db.once('open', function (callback) {
                        console.log('Insert Data');
                        var gaussSchema = mongoose.Schema({
                           Date: Date,
                           Missing: String,
                           Shoppnig: String,
                           CheckedOut: String,
                           ParkingLot: String,
                           TrolleyBay: String
                        }); 
                       // Associate the schema with the Document model
                       Document = mongoose.model('document', gaussSchema);
                       //Had to do something similar, hope this helps.

                       // Get the data from test_data.json
                       var aDocs = JSON.parse(fs.readFileSync('uploads/Updatecsvfile_x.json'));

                       // Loop through and add the sample dataset to the database
                       for (var n = 0; n < aDocs.length; n++) {
                            var docToAdd = new Document(aDocs[n]);
                            docToAdd.save(function (err, docToAdd) {
                                if (err) return console.error(err);
                            });
                        }
                    });
                      
                });
                fileStream.pipe(converter);

                /***************************** Graph ploat database in particular store wise (End)  **********************************/ 


        });

    });
    
/* File uploaded end*/

/* For Dashbord start*/
//var dbName_contact='contactlist'
//var url_contactlist= 'mongodb://localhost:27017/'+dbName_contact

var mongojs = require('mongojs');
var db_c = mongojs('carttronics', ['users']);

MongoClient.connect(url_carttronics, function (err, db) {
    if (err) {
        console.log('Unable to connect to the mongoDB server. Error:', err);
    } 
    else 
    {
        console.log('Connection Done ', url_carttronics);

        app.get('/users', function (req, res) {
            console.log("I received a get request");

            db_c.users.find(function (err, docs) {
                console.log(docs);
                res.json(docs);
            });
            
        });

        app.post('/users', function (req, res) {
            console.log(req.body);
            db_c.users.insert(req.body, function(err, doc) {
                res.json(doc);
            });
            
        });

        app.delete('/users/:id', function(req, res) {
            var id = req.params.id;
            console.log(id);
            db_c.users.remove({_id: mongojs.ObjectId(id)}, function(err, doc) {
                res.json(doc);
            })
        });

        app.get('/users/:id', function(req, res) {
            var id = req.params.id;
            console.log(id);
            db_c.users.findOne({_id: mongojs.ObjectId(id)}, function(err, doc) {
                res.json(doc);
            })
        });

        app.put('/users/:id', function(req, res) {
            var id = req.params.id;
            console.log(req.body.username);
            db_c.users.findAndModify({query: {_id: mongojs.ObjectId(id)}, 
                update: {$set: {username: req.body.username, email: req.body.email, password: req.body.password, desc: req.body.desc, roles: req.body.roles, f_name: req.body.f_name, l_name: req.body.l_name, m_name: req.body.m_name, address: req.body.address, phone: req.body.phone, s_address: req.body.s_address, city: req.body.city, s_o_pro: req.body.s_o_pro, zipcode: req.body.zipcode, country: req.body.country, b_phone: req.body.b_phone, b_f_phone: req.body.b_f_phone, fax: req.body.fax}},
                new: true}, function (err, doc) {
                    res.json(doc);
                });
        });
    }
});

/*Dashboard end*/


app.listen(3000);
console.log("server running on port 3000");