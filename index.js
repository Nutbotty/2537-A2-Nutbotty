require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

app.set('view engine', 'pug');

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {
    database
} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({
    extended: false
}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: {
        maxAge: 1 * 60 * 60 * 1000 // 1 hour in milliseconds
    }
}));


app.use(function (err, req, res, next) {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.use(function (req, res, next) {
    res.setHeader('X-Powered-By', 'Express');
    next();
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({
        username: username
    }).project({
        username: 1,
        password: 1,
        _id: 1
    }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// members section
app.get('/members', (req, res) => {
    // If the user is not currently logged in, redirect to the home page
    if (!req.session.user) {
        res.redirect('/ signin');
        return;
    }
    //make a random number between 1 and 3
    var num = Math.floor(Math.random() * 3) + 1;
    console.log(num);
    res.render('members.ejs', { userName: req.session.user.username })
});

// create one user in the database that has admin status by default
// this user will be used to log in to the admin section
app.get('/setup', async (res) => {
    const passwordHash = await bcrypt.hash('password', 10);
    const user = {
        username: 'admin',
        password: passwordHash,
        admin: true
    };
    await userCollection.insertOne(user);
    res.send(user);
});

// this is a section that only admins can access
app.get('/admin', (req, res) => {
    // If the user is not currently logged in, redirect to the home page
    if (!req.session.user) {
        res.redirect('/signin');
        return;
    }
    // If the user is not an admin, redirect to the members page
    if (!req.session.user.admin) {
        console.log('not admin');
        res.status(403);
        // res.send("Page not found - 404");
        //send a prettier html 404 error
        res.sendFile(__dirname + "/public/adminError.html");
        return;
    }
    user_array = []
    userCollection.find({}).toArray(function (err, result) {
        if (err) throw err;
        console.log('result');
        console.log(result);
        user_array = result
        res.render('admin.ejs', { users: user_array })
        app.post('/promote', async (req, res) => {
            const username = req.body.username;
            await userCollection.updateOne({ username: username }, { $set: { admin: true } });
            res.redirect('/admin');
            return;
        });
        app.post('/remove', async (req, res) => {
            const username = req.body.username;
            await userCollection.deleteOne({ username: username }, { $set: { admin: true } });
            res.redirect('/admin');
            return;
        });
    });
});


// Handle sign out form submission
app.post('/signout', (req, res) => {
    // Clear the user session and redirect to home page
    req.session.user = null;
    res.redirect('/');
    return;
});



app.use(express.static(__dirname + "/public"));

// Render the home page with the options to sign up or sign in if not currently logged in
app.get('/', (req, res) => {
    if (req.session.user) {
        // If the user is currently logged in, render the home page welcoming them and showing them the option to go to the members area and sign out
        res.render('logged_in.ejs', { userName: req.session.user.username })
    } else {
        // If the user is not currently logged in, render the home page with the options to sign up or sign in
        res.render('logged_out.ejs')
    }
});

// Render the sign up form
app.get('/signup', (req, res) => {
    res.render('signup.ejs');
});


// Handle sign up form submission
app.post('/signup', async (req, res) => {
    const {
        username,
        password,
    } = req.body;

    // Validate input
    const schema = Joi.object({
        username: Joi.string().alphanum().min(3).max(20).required(),
        password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required(),
    });
    const validationResult = schema.validate({
        username,
        password,
    });
    if (validationResult.error) {
        res.status(400).send(`Invalid username or password characters. <a href="/">Go back to home</a>`);
        return;
    }

    // Check if username already exists
    const existingUser = await userCollection.findOne({
        username: username
    });
    if (existingUser) {
        res.status(409).send(`Username already exists. <a href="/">Go back to home</a>`);
        return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = {
        username: username,
        password: hashedPassword,
        admin: false
    };
    await userCollection.insertOne(newUser);

    // Log in user
    req.session.user = newUser;

    // Redirect to members area
    res.redirect('/members');
});


// Sign in page
app.get('/signin', (req, res) => {
    // If the user is already logged in, redirect to the members page
    if (req.session.user) {
        res.redirect('/members');
        return;
    }
    // Render the sign-in form
    res.render('signin.ejs');
});


// Handle sign in form submission
app.post('/signin', async (req, res) => {
    const {
        username,
        password
    } = req.body;

    // Validate input
    const schema = Joi.object({
        username: Joi.string().alphanum().min(3).max(20).required(),
        password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required()
    });
    const validationResult = schema.validate({
        username,
        password
    });
    if (validationResult.error) {
        res.status(400).send(`Invalid username or password. <a href="/">Go back to home</a>`);
        return;
    }

    // Check if username exists
    const existingUser = await userCollection.findOne({
        username: username
    });
    if (!existingUser) {
        res.status(401).send('Invalid username or password. <a href="/">Go back to home</a>');
        return;
    }

    // Validate password
    const validPassword = await bcrypt.compare(password, existingUser.password);
    if (!validPassword) {
        res.status(401).send('Invalid username or password. <a href="/">Go back to home</a>');
        return;
    }

    // Log in user
    req.session.user = existingUser;

    // Redirect to members area
    res.redirect('/members');
});

app.get("*", (req, res) => {
    res.status(404);
    // res.send("Page not found - 404");
    //send a prettier html 404 error
    res.sendFile(__dirname + "/public/404.html");
})

// listen for requests :)
const listener = app.listen(process.env.PORT || 3000, () => {
    console.log(`Server started on port ${listener.address().port}`);
    console.log(`http://localhost:${listener.address().port}`);
    console.log(`It's Running!`);
});
