const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
    email: String,
    notification: Array,
    dummyNotification: Array,
    date: String
})

const Notification = mongoose.model("Notification", notificationSchema)

module.exports = Notification;