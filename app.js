//-----------------------------------------------------------------------------------------------------
// Description: Simple NodeJS web application with PassportJS authentication using 2 types of 
//              Strategies, local and Google. Data is persisted into the MongoDB database (via mongoose)
//
// Author: Cleyton Andre Pires (cleyton07@gmail.com)
//
// Date: jun/2022
//-----------------------------------------------------------------------------------------------------

//----------------------------------------------------------------------------------------------------- 
// Import modules
//----------------------------------------------------------------------------------------------------- 

require('dotenv').config(); //reads env variables from .env file
const express = require('express');
const mongoose = require('mongoose');  
const bodyParser = require("body-parser");
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const session = require('express-session');
const flash = require('connect-flash');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(__dirname + '/public/'));
app.use(session( {
    secret: process.env.SECRET,
    resave: false, // don't save session if unmodified
    saveUninitialized: false // don't create session until something stored
}));
app.use(passport.initialize()); // init passport on every route call.
app.use(passport.session()); // allow passport to use "express-session".
app.use(flash()); //for error/info messages

//-----------------------------------------------------------------------------------------------------
// Start server and connect to MongoDB
//-----------------------------------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server Connected to port ${PORT}`));

mongoose.connect('mongodb://localhost:27017/userDB').catch(error => console.log(error));

//----------------------------------------------------------------------------------------------------- 
// Mongoose Schemas (User and Secret)
//----------------------------------------------------------------------------------------------------- 
const userSchema = new mongoose.Schema ({
    username: String,
    googleId: String
});

const secretSchema = new mongoose.Schema ({
    user_id: {
        type: mongoose.ObjectId,
        unique: false,
        required: true,
    },
    secret: {
        type: String,
        required: true
    }
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
const Secret = new mongoose.model("Secret", secretSchema);

passport.serializeUser(function(user, done) {  // used to serialize the user for the session
    done(null, user.id); 
});

passport.deserializeUser(function(id, done) { // used to deserialize the user
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

//----------------------------------------------------------------------------------------------------- 
// PassportJS strategies (local and Google)
//----------------------------------------------------------------------------------------------------- 

// Create local strategy
passport.use(User.createStrategy());

// Create Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    scope: ["profile", "email"]    
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id, username: profile.emails[0].value }, function (err, user) {
      return cb(err, user);
    });
  }
));


//----------------------------------------------------------------------------------------------------- 
// Aux funtions
//----------------------------------------------------------------------------------------------------- 

// Check if the user is authenticated
function loggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        next();
    } else {
        req.flash('info', ['User not authenticated! Please log in.']);  
        res.redirect('/login');
    }
}

//----------------------------------------------------------------------------------------------------- 
// Routes handlers
//----------------------------------------------------------------------------------------------------- 

// Home page
app.get('/', (req, res) => {
    res.render('home');
});

// Local strategy login routes
app.get('/login', (req, res) => {
     if(req.session.messages) { // set by passport.authenticate() failureRedirect (failureMessage: true)
        req.flash('info', req.session.messages);  
        req.session.messages = null;  
    }
    res.render('login', {messages: req.flash('info')});
});

app.post('/auth/login', 
         passport.authenticate('local', { successRedirect: '/secrets',  failureRedirect: '/login', failureMessage: true  })   
);


// Google Strategy login and register routes
app.get('/auth/google', passport.authenticate('google', {prompt : "select_account"})); //always prompt the user to select his account

app.get("/auth/google/secrets",
        passport.authenticate("google", { failureRedirect: "/login", failureMessage: true }),
                              function (req, res) {res.redirect("/secrets");} // Successful authentication, redirect to secrets page.
);

// Register routes (only for local strategy)
app.get('/register', 
        function(req, res) { res.render('register', {messages: req.flash('info')});
});

app.post('/register', function(req, res) {
     User.register( {username: req.body.username}, req.body.password, 
                    function(err, user) {
                        if(err) {
                            req.flash('info', err.message);
                            res.redirect("/register");
                        } else {
                            passport.authenticate("local")(req, res, function() {res.redirect("/secrets");});
                        }
                    });
});

// route to the secured secrets page
app.get('/secrets', loggedIn, (req, res) => {
    const secrets = Secret.find({user_id: req.user._id}, function(err, docs) {
        if (err) {
            console.log(err);
            next(err);
        }
        else {
            res.render('secrets', {user: req.user, secrets: docs});
        }
    });    
});

// Form to Submit a new secret 
app.get("/submit", loggedIn, function(req, res) {
    res.render('submit');
});

// handle new secret submitted by the user
app.post("/submit", loggedIn, function(req, res) {
    const secret = req.body.secret;
    var newSecret = new Secret({ user_id: req.user._id, secret: secret });

    newSecret.save(function (err) { //save new secret to the database
        if (err) {
            console.log(err);
        }   
    });

    res.redirect('/secrets');    
});


// Logout is now an asyncrhonous funtction 
// See: https://medium.com/passportjs/fixing-session-fixation-b2b68619c51d
// It is a good idea to use POST or DELETE requests instead of GET requests 
// for the logout endpoints, in order to prevent accidental or malicious logouts.
// See: https://www.passportjs.org/concepts/authentication/logout/
app.post("/logout", function(req, res) {
                        req.logout(function(err) {
                            if (err) { return next(err); }
                            res.redirect('/');
                        });
});
