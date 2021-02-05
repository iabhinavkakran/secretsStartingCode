require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

app.use(session({
    secret: "Our Little Secret.",
    resave: false,
    saveUninitialized: true,
  }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useUnifiedTopology: true, useNewUrlParser: true})
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    gmailId: String,
    secret: String,
    abhinavId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User =new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });
///////GOOGLE LOGIN/////////
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) { 

    User.findOne( {gmailId : profile.id}, function( err, foundUser ){
        if( !err ){                                                          //Check for any errors
            if( foundUser ){                                          // Check for if we found any users
                return cb( null, foundUser );                  //Will return the foundUser
            }else {                                                        //Create a new User
                const newUser = new User({
                    gmailId : profile.id
                });
                console.log(newUser);
                newUser.save( function( err ){
                    if(!err){
                        return cb(null, newUser);                //return newUser
                    }
                });
            }
        }else{
            console.log( err );
        }
    });
  }
));
/////////FACEBOOK LOGIN/////////
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      
    User.findOrCreate({ abhinavId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
    res.render("home");
});

//GOOGLE ACCOUNT AUTHENTICTION//////

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

////FACEBOOK ACCOUNT AUTHENTICATION//////
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });  

/////////////////////////////////////////////////////////////

app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUser){
        if(err){
            console.log(err)
        }else{
            if(foundUser){
                res.render("secrets", {userWithSecrets: foundUser});
            }
        }
    })
});

app.get("/submit", function(req, res){
    if(req.isAuthenticated()){
        res.render("submit");
    }else{
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res){
    const secretSubmitted = req.body.secret;
    
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = secretSubmitted;
                foundUser.save(function(){
                    res.redirect("/secrets");
                })
            }
        }
    })
});

app.get("/register", function(req, res){
    res.render("register");
});
app.post("/register", function(req, res){
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({username: username}, function(err, foundOne){
        if(err){
            console.log(err);
        }else{
            if(foundOne){
                res.render("foundOne");
            }else{
                User.register({username: username}, password, function(err, result){
                    if(err){
                        res.redirect("/register");
                    }else{
                        passport.authenticate("local")(req, res, function(){
                            res.redirect("secrets");
                        });
                    }
                });
            }
        }
    });
});

app.get("/login", function(req, res){
    res.render("login");
});
app.post("/login", function(req, res){
    const username = req.body.username;
    const password = req.body.password;

    const user = new User({
        username: username,
        password: password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }else{
            passport.authenticate('local', {failureRedirect: "wrongPassword" })(req, res, function(){
                                        res.redirect("secrets");
                                    });
        }
    });   
});

app.get("/logout", function(req, res){
    req.logOut();
    res.redirect("/");
});
app.get("/wrongPassword", function(req, res){
    res.render("wrongPassword");
});

app.listen(3000, function(){
    console.log("Server Started at 3000");
});
