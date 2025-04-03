const axios = require("axios");

const verifyRecaptcha = async (req, res, next) => {
    const recaptchaToken = req.body["g-recaptcha-response"];
    if (!recaptchaToken) {
        req.flash("error", "Please complete the reCAPTCHA.");
        return res.render("index", { formData: req.body });
    }

    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify`, null, {
            params: {
                secret: process.env.RECAPTCHA_SECRET_KEY,
                response: recaptchaToken,
            },
        });

        if (!response.data.success) {
            req.flash("error", "Failed reCAPTCHA verification. Please try again.");
            return res.render("index", { formData: req.body });
        }

        next();
    } catch (error) {
        console.error("❌ Error verifying reCAPTCHA:", error);
        req.flash("error", "An error occurred during reCAPTCHA verification.");
        return res.render("index", { formData: req.body });
    }
};

module.exports = verifyRecaptcha;
