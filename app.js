//jshint esversion:6
import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import ejs from 'ejs';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
// GoogleStrategy = require('passport-google-oauth20').Strategy;
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import findOrCreate from 'mongoose-findorcreate';

const app = express();
const port = process.env.PORT || 3000;

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended : true
}));

app.use(session({
    secret : "KarthikIsASuperHero",
    resave : false,
    saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());

// Database configuration
mongoose.connect('mongodb://localhost:27017/secretsDB');

const userSchema = new mongoose.Schema({
    email : {       
            type : String, 
            lowercase : true,
            trim : true,
            match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']      
    },
    password : {
        type : String,
    },
    googleId : String,
    secret : String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
)); 

//handlers
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get('/', (req, res) => {
    res.render("home.ejs");
}) 

app.get('/register', (req, res) => {
    res.render("register.ejs");
})

app.get('/login', (req, res) => {
    res.render("login.ejs");
})

app.get('/secrets', (req, res) => {
    User.find({secret : {$ne : null}})
    .then(result => {
        res.render('secrets.ejs', {allUsersWithSecrets : result});
    })
    .catch(err => {
        console.log(err);
    })
})

app.get('/submit', (req, res) => {
    if(req.isAuthenticated()) {
        res.render('submit.ejs');
    } else {
        res.render('register.ejs', {mess : "Unauthorized access. First register and login to our website"});
    }
})

app.post('/submit', (req, res) => {
    const secret = req.body.secret;

    User.findById({_id : req.user.id})
    .then(result => {
        if(result) {
            result.secret = secret;
            result.save()
            .then(()=> {
                res.redirect('/secrets');
            })
        }
    })
    .catch(err => {
        console.log(err);
    })
})

app.post('/register', (req, res) => {
    console.log(req.body);
    User.register({ username: req.body.username, email : req.body.username}, req.body.password)
    .then(result => {
        if (result) {
            passport.authenticate("local")(req, res, () => {
                res.render('login.ejs', {mess : "Sign-Up complete. Try logging in"});
                // res.redirect('/secrets');
            });
        } else {
            console.log(result);
            res.redirect('/');
        }
    })
    .catch(err => {
        if (err.name === "UserExistsError") {
            res.render('register.ejs', { mess: "Account already exists. Try logging in" });
        } else {
            console.log(err);
        }
    });
});

app.post('/login', (req, res) => {
    const user = new User({
        username : req.body.username,
        password : req.body.password
    });

    console.log(req.body);
    User.findOne({email : req.body.username})
    .then(result => {
        if(result) {
            console.log(result);
            req.login(user, (err) => {
                try {
                    if(err) {
                        console.log(err);
                        res.render('login.ejs', {mess : err.message});
                    } else {
                        passport.authenticate('local')(req, res, ()=> {
                            res.redirect('/secrets');
                        })
                    }
                }catch(err) {
                    console.log(err);   
                }
            })
        } else {
            console.log(result);
            res.render('login.ejs', {
                mess : "Account doesn't exist. First register yourself"
            })
        }
    })
    .catch(err => {
        console.log(err);
        res.render('login.ejs', {
            mess : "Account doesn't exist. First register yourself"
        })
    })
    
})



app.get('/logout', (req, res) => {
    req.logout((err)=>{
        if(err) {
            console.log(err);
        }
    });
    res.redirect('/')
})

app.listen(port, ()=> {
    console.log('Server started at port ' + port);
})