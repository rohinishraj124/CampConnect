const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/yelp-camp');

const Campground = require('../models/campground');
const cities = require('./cities');
const { places, descriptors } = require('./seedHelpers');

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:'));
db.once('open', () => {
    console.log('Database connected');
});
const sample = (array) => array[Math.floor(Math.random() * array.length)];


const seedDB = async () => {
    await Campground.deleteMany({});
    for (let i = 0; i < 5; i++) {
        const random1000 = Math.floor(Math.random() * 88);
        const camp = new Campground({
            author: '670a7bee62f677be5def69b7',
            location: `${cities[random1000].city}, ${cities[random1000].state}`,
            title: `${sample(descriptors)} ${sample(places)}`,
            description: 'Lorem ipsum dolor sit amet consectetur adipisicing elit. Iure, quidem! ',
            price: Math.floor(Math.random() * 20) + 10,
            geometry: {
                type: "Point",
                coordinates: [
                    cities[random1000].longitude,
                    cities[random1000].latitude
                ]
            },
            images: [
                {
                    url: 'https://res.cloudinary.com/djxqhqu5l/image/upload/v1729007313/CampConnect/rpedhv3yssca9gg9eub6.jpg',
                    filename: 'CampConnect/rpedhv3yssca9gg9eub6',
                },
                {
                    url: 'https://res.cloudinary.com/djxqhqu5l/image/upload/v1729007315/CampConnect/oxklet13twzint8vd6bn.jpg',
                    filename: 'CampConnect/oxklet13twzint8vd6bn',
                }
            ],
        });
        await camp.save();
    }
}

seedDB().then(() => {
    mongoose.connection.close();
});


