//jshint esversion:6
import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import ejs from 'ejs';
import mongoose from 'mongoose';
// import encrypt from 'mongoose-encryption';
// import md5 from 'md5';
import bcrypt from 'bcrypt';

const app = express();
const port = process.env.PORT || 3000;
const saltRound = 10;

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended : true
}));

// Database configuration
mongoose.connect('mongodb://localhost:27017/secretsDB');

const userSchema = new mongoose.Schema({
    email : {       
            type : String, 
            unique : true,
            lowercase : true,
            trim : true,
            required : true,
            match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']      
    },
    password : {
        type : String,
        required : true
    }
})

// userSchema.plugin(encrypt, {secret : process.env.SECRETSTRING, encryptedFields : ["password"]});

const User = mongoose.model('User', userSchema);

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

app.post('/register', (req, res) => {
    
    User.findOne({email : req.body.email})
    .then(result => {
        if(result) {
            console.log("Email already exists. Try logging in");
            res.render('register', {
                mess : "Email already exists. Try logging in"
            });

        } else {
            bcrypt.hash(req.body.password, saltRound)
            .then(pass => {
                const userData = new User({
                    email : req.body.email,
                    // password : md5(req.body.password)
                    password : pass
                });

            userData.save()
            .then(result => {
                console.log(result + "\n New user has been created.");
                res.redirect('/login');
            })
            .catch(err => {
                if(err.name === "ValidationError") {
                    res.render('register', {
                        mess : err.message
                    })
                } else {
                    console.log(err);
                }
            })
            })

            
        }
    })
})

app.post('/login', (req, res) => {
    User.findOne({email : req.body.email})
    .then(result => {
        if(!result) {
            res.render('register.ejs', {
                mess : "Account doesn't exist. Please register yourself first!"
            })
        } else {
            bcrypt.compare(req.body.password, result.password)
            .then(result => {
                if(result) {
                    res.render('secrets.ejs');
                    console.log("login succesfull");
                }else {
                    res.render("login", {
                        mess : "Password doesn't match!"
                    })
                }
            })
        }
    }).catch(err => {
        console.log(err);
    })
})

app.get('/logout', (req, res) => {
    res.render('home.ejs')
})

app.listen(port, ()=> {
    console.log('Server started at port ' + port);
})