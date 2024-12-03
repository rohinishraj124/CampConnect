// ********************************************************************************
// EXPRESS SETUP
// *******************************************************************************
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const app = express();
const ejsMate = require('ejs-mate');
const ExpressError = require('./utils/ExpressError.js');
const { campgroundSchema, reviewSchema } = require('./Schemas.js');
const catchAsync = require('./utils/catchAsync.js');
const Joi = require('joi');
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

// Routes
const campgroundsRoutes = require('./routes/campgrounds');
const reviewRoutes = require('./routes/reviews');
const usersRoutes = require('./routes/users');
const dbUrl = process.env.DB_URL || 'mongodb://localhost:27017/yelp-camp';

// *******************************************************************************
// MONGOOSE SETUP
// *******************************************************************************
const mongoose = require('mongoose');
mongoose.connect(dbUrl, {
    serverSelectionTimeoutMS: 5000 // Timeout for database connection
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Database connected');
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.engine('ejs', ejsMate);
app.use(express.static(path.join(__dirname, 'public')));
app.use(mongoSanitize());
app.use(methodOverride('_method'));

// Helmet configuration with custom CSP
app.use(helmet());
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
    "https://cdn.jsdelivr.net",
    "https://cdn.maptiler.com/"
];

const connectSrcUrls = [
    "https://api.maptiler.com/",
];

const fontSrcUrls = []; // Add any additional font sources if needed

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
                "https://api.maptiler.com/"
            ],
        },
    })
);


// Session configuration with connect-mongo
const MongoStore = require('connect-mongo');
const sessionConfig = {
    store: MongoStore.create({
        mongoUrl: dbUrl,
        crypto: { secret: process.env.SESSION_SECRET || 'fallbackSecret' }
    }),
    name: 'session',
    secret: process.env.SESSION_SECRET || 'fallbackSecret',
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        expires: Date.now() + 1000 * 60 * 60 * 24 * 7, // 1 week
        maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
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
app.get('/', (req, res) => {
    res.render('home');
});
app.use('/', usersRoutes);
app.use('/campgrounds', campgroundsRoutes);
app.use('/campgrounds/:id/reviews', reviewRoutes);

//*******************************************************************************
// ROUTES FOR ERROR HANDLING
//*******************************************************************************
app.all('*', (req, res, next) => {
    next(new ExpressError('Page Not Found', 404));
});
app.use((err, req, res, next) => {
    const { statusCode = 500 } = err;
    if (!err.message) err.message = 'Oh No, Something Went Wrong!';
    res.status(statusCode).render("error", { err });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
