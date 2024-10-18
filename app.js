// ********************************************************************************
// EXPRESS SETUP
// *******************************************************************************
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const ejsMate = require('ejs-mate');
const ExpressError = require('./utils/ExpressError.js');
const { campgroundSchema, reviewSchema } = require('./Schemas.js');
const catchAsync = require('./utils/catchAsync.js');
const Review = require('./models/review.js');
const session = require('express-session');
const flash = require('connect-flash');
const Campground = require('./models/campground.js');
const passport = require('passport');
const LocalStrategy = require('passport-local');
const User = require('./models/user.js');
const mongoSanitize = require('express-mongo-sanitize');
const helmet = require('helmet');
const methodOverride = require('method-override');

const campgroundsRoutes = require('./routes/campgrounds');
const reviewRoutes = require('./routes/reviews');
const usersRoutes = require('./routes/users');
const dbUrl = process.env.DB_URL || 'mongodb://127.0.0.1:27017/yelp-camp'; // Bind IP

// *******************************************************************************
// MONGOOSE SETUP
// *******************************************************************************
const mongoose = require('mongoose');
mongoose.connect(dbUrl, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Database connected');
});

// Express setup
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('ejs', ejsMate);
app.use(express.static(path.join(__dirname, 'public')));
app.use(mongoSanitize());

// Security headers
app.use(helmet());
app.use((req, res, next) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' https://*;");
    next();
});

// Content Security Policy
const scriptSrcUrls = [
    "https://stackpath.bootstrapcdn.com/",
    "https://kit.fontawesome.com/",
    "https://cdnjs.cloudflare.com/",
    "https://cdn.jsdelivr.net",
    "https://cdn.maptiler.com/",
    "https://code.jquery.com"
];

const styleSrcUrls = [
    "https://kit-free.fontawesome.com/",
    "https://stackpath.bootstrapcdn.com/",
    "https://fonts.googleapis.com/",
    "https://use.fontawesome.com/",
    "https://cdn.jsdelivr.net/",
    "https://cdn.maptiler.com/"
];

const connectSrcUrls = [
    "https://api.maptiler.com/",
];

app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            connectSrc: ["'self'", ...connectSrcUrls],
            scriptSrc: ["'unsafe-inline'", "'self'", ...scriptSrcUrls],
            styleSrc: ["'self'", "'unsafe-inline'", ...styleSrcUrls],
            workerSrc: ["'self'", "blob:"],
            imgSrc: ["'self'", "blob:", "data:", "https://res.cloudinary.com/djxqhqu5l/", "https://imgs.search.brave.com", "https://api.maptiler.com/"],
        },
    })
);

app.use(methodOverride('_method'));

const sessionConfig = {
    name: 'session',
    secret: process.env.SECRET || 'thisshouldbeabettersecret!',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
};

app.use(session(sessionConfig));
app.use(flash());

app.use(passport.initialize());
app.use(passport.session());
passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.use((req, res, next) => {
    res.locals.currentUser = req.user;
    res.locals.success = req.flash('success');
    res.locals.error = req.flash('error');
    next();
});

// Routes
app.get('/', async (req, res) => {
    res.render('home');
});

app.use('/', usersRoutes);
app.use('/campgrounds', campgroundsRoutes);
app.use('/campgrounds/:id/reviews', reviewRoutes);

// Error handling
app.all('*', (req, res, next) => {
    next(new ExpressError('Page Not Found', 404));
});

app.use((err, req, res, next) => {
    const { statusCode = 500 } = err;
    if (!err.message) err.message = 'Oh No, Something Went Wrong!';
    res.status(statusCode).render("error", { err });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
