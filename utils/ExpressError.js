class ExpressError extends Error {
    constructor(message, statusCode) {
        super();
        this.message = message;
        this.statusCode = statusCode;
        console.log(`Error ${statusCode}: ${message}`);
    }
}

module.exports = ExpressError;