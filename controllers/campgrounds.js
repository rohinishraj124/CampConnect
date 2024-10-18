const Campground = require('../models/campground');
const { cloudinary } = require("../cloudinary");
const maptilerClient = require("@maptiler/client");
maptilerClient.config.apiKey = process.env.MAPTILER_API_KEY;

module.exports.index = async (req, res) => {
    try {
        const campgrounds = await Campground.find({});
        if (!campgrounds.length) {
            req.flash('error', 'No campgrounds found');
            return res.redirect('/');
        }
        res.render('campgrounds/index', { campgrounds });
    } catch (error) {
        req.flash('error', 'Failed to retrieve campgrounds');
        res.redirect('/');
    }
};

module.exports.renderNewForm = (req, res) => {
    res.render('campgrounds/new');
};

module.exports.createCampground = async (req, res, next) => {
    try {
        const geoData = await maptilerClient.geocoding.forward(req.body.campground.location, { limit: 1 });
        if (!geoData.features.length) {
            req.flash('error', 'Location not found');
            return res.redirect('/campgrounds/new');
        }

        const campground = new Campground(req.body.campground);
        campground.geometry = geoData.features[0].geometry;
        campground.images = req.files.map(f => ({ url: f.path, filename: f.filename }));
        campground.author = req.user._id;

        await campground.save();
        req.flash('success', 'Successfully made a new campground!');
        res.redirect(`/campgrounds/${campground._id}`);
    } catch (error) {
        next(error);
    }
};

module.exports.showCampground = async (req, res) => {
    try {
        const campground = await Campground.findById(req.params.id)
            .populate({ path: 'reviews', populate: { path: 'author' } })
            .populate('author');
        
        if (!campground) {
            req.flash('error', 'Campground not found');
            return res.redirect('/campgrounds');
        }
        res.render('campgrounds/show', { campground });
    } catch (error) {
        req.flash('error', 'Failed to retrieve campground');
        res.redirect('/campgrounds');
    }
};

module.exports.renderEditForm = async (req, res) => {
    try {
        const campground = await Campground.findById(req.params.id);
        if (!campground) {
            req.flash('error', 'Campground not found');
            return res.redirect('/campgrounds');
        }
        res.render('campgrounds/edit', { campground });
    } catch (error) {
        req.flash('error', 'Failed to retrieve campground for editing');
        res.redirect('/campgrounds');
    }
};

module.exports.updateCampground = async (req, res) => {
    const { id } = req.params;
    try {
        const campground = await Campground.findByIdAndUpdate(id, { ...req.body.campground }, { new: true });

        const geoData = await maptilerClient.geocoding.forward(req.body.campground.location, { limit: 1 });
        if (!geoData.features.length) {
            req.flash('error', 'Location not found');
            return res.redirect(`/campgrounds/${campground._id}/edit`);
        }
        
        campground.geometry = geoData.features[0].geometry;
        
        const imgs = req.files.map(f => ({ url: f.path, filename: f.filename }));
        campground.images.push(...imgs);
        
        await campground.save();

        if (req.body.deleteImages && req.body.deleteImages.length) {
            for (let filename of req.body.deleteImages) {
                await cloudinary.uploader.destroy(filename);
            }
            await campground.updateOne({ $pull: { images: { filename: { $in: req.body.deleteImages } } } });
        }
        
        req.flash('success', 'Successfully updated campground!');
        res.redirect(`/campgrounds/${campground._id}`);
    } catch (error) {
        req.flash('error', 'Failed to update campground');
        res.redirect(`/campgrounds/${id}/edit`);
    }
};

module.exports.deleteCampground = async (req, res) => {
    const { id } = req.params;
    try {
        const deletedCampground = await Campground.findByIdAndDelete(id);
        if (!deletedCampground) {
            req.flash('error', 'Campground not found');
            return res.redirect('/campgrounds');
        }
        req.flash('success', 'Successfully deleted the campground!');
        res.redirect('/campgrounds'); // Redirect to the list of campgrounds
    } catch (error) {
        req.flash('error', 'Failed to delete campground');
        res.redirect('/campgrounds');
    }
};
