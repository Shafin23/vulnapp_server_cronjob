const mongoose = require("mongoose");

const masterDBSchema = new mongoose.Schema({
    logo: { type: String },
    program: { type: String, required: true, index: true }, // Changed to String for clarity
    version: { type: String, required: true, index: true },
    companyDomain: { type: [String], index: true }, // Array of strings
    matchedSoftwareName: { type: String, index: true },
    matchedSoftwareVersion: { type: String },
    status: { type: String },
    vulnerability: { type: Array, index: true }, // Array of strings
    dummyVulnerability: { type: Array, index: true }, // Array of strings
    deletedVulnerability: { type: Array, index: true }, // Array of strings
    dummyThreats: { type: Array }, // Array of strings
    threats: { type: Array }, // Array of strings
    risk: { type: String },
    source: { type: String },
    ip_address: { type: Array } // Array of strings
}, {
    timestamps: true // Automatically add createdAt and updatedAt fields
});

// Add compound index if needed
masterDBSchema.index({ program: 1, version: 1, companyDomain: 1 });

const MasterDB = mongoose.model("MasterDB", masterDBSchema);
module.exports = MasterDB;
