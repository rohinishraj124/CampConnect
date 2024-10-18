// utils/catchAsync.js
module.exports = (fn) => {
    return (req, res, next) => {
        if (typeof fn !== 'function') {
            console.error('Provided fn is not a function:', fn);
            return next(new TypeError('Expected fn to be a function'));
        }
        Promise.resolve(fn(req, res, next)).catch(next); // Use Promise.resolve to handle non-promises
    };
};
