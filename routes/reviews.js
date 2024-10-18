const express = require('express');
const router = express.Router({ mergeParams: true });
const Review = require('../models/review.js');
const catchAsync = require('../utils/catchAsync');
const ExpressError = require('../utils/ExpressError');
const { reviewSchema } = require('../Schemas.js');
const Campground = require('../controllers/campgrounds.js');
const review = require('../controllers/reviews.js');
const { validateReview, isLoggedIn, isReviewAuthor } = require('../middleware');

//******************************************************************************
//ROTES FOR REVIEW SECTION
//******************************************************************************

router.post('/', validateReview, isLoggedIn, catchAsync(review.createReview));

router.delete('/:reviewId', isLoggedIn, isReviewAuthor, catchAsync(review.deleteReview));


module.exports = router;





