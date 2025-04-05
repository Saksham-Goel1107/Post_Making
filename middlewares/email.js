const { transporter } = require("./email.config.js");
const { Verification_Email_Template, Welcome_Email_Template, Reseting_Verification_Email_Template, Email_password_change_Template } = require("./emailTemplate.js");

const sendVerificationEmail = async (email, verificationCode) => {
    try {
        const response = await transporter.sendMail({
            from: '"Saksham-Goel1107" <no-reply@saksham.com>',
            to: email,
            subject: "Verify your Email",
            text: "Verify your Email",
            html: Verification_Email_Template.replace("{verificationCode}", verificationCode),
        });
        console.log('Verification email sent successfully', response);
    } catch (error) {
        console.log('Error sending verification email', error);
    }
};

const sendResetingVerificationEmail = async (email, verificationCode) => {
    try {
        const response = await transporter.sendMail({
            from: '"Saksham-Goel1107" <no-reply@saksham.com>',
            to: email,
            subject: "Password Reseting Email",
            text: "Verify your Password Reseting Request",
            html: Reseting_Verification_Email_Template.replace("{verificationCode}", verificationCode),
        });
        console.log('Verification email sent successfully', response);
    } catch (error) {
        console.log('Error sending verification email', error);
    }
};

const sendWelcomeEmail = async (email, name) => {
    try {
        const response = await transporter.sendMail({
            from: '"Saksham-Goel1107" <no-reply@saksham.com>',
            to: email,
            subject: "Welcome to Our Community",
            text: "Welcome to Our Community",
            html: Welcome_Email_Template.replace("{name}", name),
        });
        console.log('Welcome email sent successfully', response);
    } catch (error) {
        console.log('Error sending welcome email', error);
    }
};

const sendpasswordchangetemplate = async (email, name) => {
    try {
        const response = await transporter.sendMail({
            from: '"Saksham-Goel1107" <no-reply@saksham.com>',
            to: email,
            subject: "Password Changed",
            text: "Your Account Password Has Been Changed",
            html: Email_password_change_Template.replace("{name}", name),
        });
        console.log('Welcome email sent successfully', response);
    } catch (error) {
        console.log('Error sending welcome email', error);
    }
};

module.exports = { sendVerificationEmail, sendWelcomeEmail, sendResetingVerificationEmail, sendpasswordchangetemplate};
