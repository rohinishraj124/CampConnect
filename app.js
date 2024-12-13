// ********************************************************************************
// EXPRESS SETUP
// *******************************************************************************
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const ejsMate = require('ejs-mate');
const session = require('express-session');
const flash = require('connect-flash');
const mongoose = require('mongoose');
const methodOverride = require('method-override');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const MongoStore = require('connect-mongo');
const ExpressError = require('./utils/ExpressError');
const catchAsync = require('./utils/catchAsync');

// Models
const User = require('./models/user');
const Campground = require('./models/campground');
const Review = require('./models/review');

// Routes
const campgroundsRoutes = require('./routes/campgrounds');
const reviewRoutes = require('./routes/reviews');
const usersRoutes = require('./routes/users');

// Database Setup
const dbUrl = process.env.DB_URL || 'mongodb://localhost:27017/yelp-camp';

mongoose.connect(dbUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Database connected');
}).catch((err) => {
    console.error('Database connection error:', err);
});

// Express Configuration
const app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('ejs', ejsMate);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(methodOverride('_method'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(mongoSanitize());

// Debugging Middleware
app.use((req, res, next) => {
    console.log(`Request URL: ${req.url}`);
    console.log(`Request Method: ${req.method}`);
    next();
});

// Security: Content Security Policy
const scriptSrcUrls = [
    "https://stackpath.bootstrapcdn.com/",
    "https://kit.fontawesome.com/",
    "https://cdnjs.cloudflare.com/",
    "https://cdn.jsdelivr.net",
    "https://cdn.maptiler.com/",
    "https://code.jquery.com",
];

const styleSrcUrls = [
    "https://kit-free.fontawesome.com/",
    "https://stackpath.bootstrapcdn.com/",
    "https://fonts.googleapis.com/",
    "https://use.fontawesome.com/",
    "https://cdn.jsdelivr.net",
    "https://cdn.maptiler.com/",
];

const connectSrcUrls = [
    "https://api.maptiler.com/",
];

const fontSrcUrls = [];

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            connectSrc: ["'self'", ...connectSrcUrls],
            scriptSrc: ["'unsafe-inline'", "'self'", ...scriptSrcUrls],
            styleSrc: ["'self'", "'unsafe-inline'", ...styleSrcUrls],
            workerSrc: ["'self'", "blob:"],
            fontSrc: ["'self'", "https://fonts.googleapis.com", "https://fonts.gstatic.com", ...fontSrcUrls],
            objectSrc: [],
            imgSrc: [
                "'self'",
                "blob:",
                "data:",
                "https://res.cloudinary.com/djxqhqu5l/", // Your Cloudinary account
                "https://imgs.search.brave.com",
                "https://api.maptiler.com/",
            ],
        },
    })
);

// Session Configuration
const secret = process.env.SESSION_SECRET || 'thisshouldbeabettersecret!';
const sessionConfig = {
    name: 'session',
    secret,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: dbUrl }),
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7, // 1 week
        maxAge: 1000 * 60 * 60 * 24 * 7,
    },
};

app.use(session(sessionConfig));
app.use(flash());

// Passport Configuration
app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

// Middleware for Flash Messages
app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// Routes
app.get('/', (req, res) => {
    res.render('home');
});

app.use('/', usersRoutes);
app.use('/campgrounds', campgroundsRoutes);
app.use('/campgrounds/:id/reviews', reviewRoutes);

// Debugging Route
app.get('/debug', (req, res) => {
    res.send('Debugging Route Working');
});

// Authentication Debugging
app.post('/login', passport.authenticate('local', {
    failureFlash: true,
    failureRedirect: '/login'
}), (req, res) => {
    const redirectUrl = req.session.returnTo || '/campgrounds';
    delete req.session.returnTo; // Clear session returnTo after redirecting
    res.redirect(redirectUrl);
});

// Error Handling
app.all('*', (req, res, next) => {
    next(new ExpressError('Page Not Found', 404));
});

app.use((err, req, res, next) => {
    const { statusCode = 500 } = err;
    if (!err.message) err.message = 'Oh No, Something Went Wrong!';
    console.error(err.stack); // Log error for debugging
    res.status(statusCode).render('error', { err });
});

// Start the Server
const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
