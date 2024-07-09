const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
    first_name: {
        type: String,
        required: true,
        trim: true
    },
    last_name: {
        type: String,
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true, // Ensure email is unique
        trim: true,
        lowercase: true
    },
    company_name: {
        type: String,
        required: true,
        trim: true
    },
    company_domain: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    phone_number: {
        type: String,
        required: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    confirm_password: {
        type: String
    },
    two_factor_auth: {
        type: Boolean,
        required: true,
        default: false // Set default value
    },
    companyDomainToken: {
        type: String,
        required: true
    },
    userAuthenticationToken: {
        type: String
    },
    status: {
        type: String,
        default: "inactive" // Set default value
    },
    userRole: {
        type: String,
        default: "user" // Set default value
    },
    notification: {
        type: Array, // Array of strings
        default: []
    },
    dummyNotification: {
        type: Array, // Array of strings
        default: []
    },
    isInvited: {
        type: Boolean,
        default: false // Set default value
    },
    lastLoginDate: {
        type: Date // Use Date type for better handling of dates
    },
    isNotificationOn: {
        type: Boolean,
        default: true // Set default value
    }
}, {
    timestamps: true // Automatically add createdAt and updatedAt fields
});

// Adding indexes
userSchema.index({ email: 1 });
userSchema.index({ company_domain: 1 });
userSchema.index({ userRole: 1 });

const User = mongoose.model("User", userSchema);

module.exports = User;
