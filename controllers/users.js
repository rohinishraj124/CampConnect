// controllers/users.js
const User = require('../models/user'); // Ensure this path is correct
const catchAsync = require('../utils/catchAsync'); // Ensure this path is correct


module.exports.renderRegister = (req, res) => {
    res.render('users/register');
};

module.exports.register = catchAsync(async (req, res, next) => {
    const { email, username, password } = req.body;
    const user = new User({ email, username });
    const registeredUser = await User.register(user, password);

    req.login(registeredUser, (err) => {
        if (err) return next(err);
        req.flash('success', 'Welcome to Yelp Camp!');
        res.redirect('/campgrounds');
    });
});

module.exports.renderLogin = (req, res) => {
    res.render('users/login');
};

module.exports.login = (req, res) => {
    req.flash('success', 'Welcome back!');
    const redirectUrl = res.locals.returnTo || '/campgrounds'; // Redirect to returnTo or default
    res.redirect(redirectUrl);
};

module.exports.logout = (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);
        req.flash('success', 'Goodbye!');
        res.redirect('/'); // Redirect to home after logout
    });
};
