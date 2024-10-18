// routes/users.js
const express = require('express');
const router = express.Router();
const passport = require('passport');
const catchAsync = require('../utils/catchAsync'); // Ensure this path is correct
const user = require('../controllers/users'); // Ensure this path is correct
const { storeReturnTo } = require('../middleware'); // Ensure this path is correct

// Registration routes

router.route('/register')
    .get(user.renderRegister)
    .post(catchAsync(user.register)); // Ensure user.register is defined

// Login routes
router.route('/login')
    .get(user.renderLogin)
    .post(
        storeReturnTo,
        passport.authenticate('local', { failureFlash: true, failureRedirect: '/login' }),
        user.login
    );

// Logout route
router.get('/logout', user.logout);

module.exports = router;
