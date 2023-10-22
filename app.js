//jshint esversion:6
import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import ejs from 'ejs';
import mongoose from 'mongoose';
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';

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
    }
})

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

//handlers
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
    if(req.isAuthenticated()) {
        res.render('secrets.ejs');
    } else {
        res.render('register.ejs', {mess : "Unauthorised access. First register and login to our website"});
    }
})

app.post('/register', (req, res) => {
    console.log(req.body);
    User.register({ username: req.body.username}, req.body.password)
    .then(result => {
        if (result) {
            passport.authenticate("local")(req, res, () => {
                res.redirect('/secrets');
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