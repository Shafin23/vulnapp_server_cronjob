const express = require("express");
const mongoose = require("mongoose");
const http = require("http");
const socketIo = require("socket.io");
const nodemailer = require("nodemailer");
const NodeCache = require("node-cache");
const { callApi } = require("./callApiFunction")
const MasterDB = require("./schemas/masterDBSchema");
const User = require("./schemas/userSchema");
const Notification = require("./schemas/notificationSchema")
const cron = require('node-cron');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);
const cache = new NodeCache({ stdTTL: 31536000 });

const cachingMasterDb = async () => {
    const existingMasterDB = await MasterDB.find();
    cache.set("masterDB", existingMasterDB);
};

// Set up Nodemailer transporter
const transporter = nodemailer.createTransport({
    service: 'Gmail', // Your email service provider
    auth: {
        user: 'shafinahnam89@gmail.com', // Your email address
        pass: 'etoytxvjxixpooow' // Your email password
    }
});

// Basic route to verify the server is working
app.get("/", (req, res) => {
    res.json({ Message: "API Server is running" });
});

// Connecting MongoDB database through mongoose
mongoose.connect("mongodb+srv://test25042000:dSrlxmtLdGGaW6TJ@cluster0.6oyupqe.mongodb.net/test")
    .then(() => {
        cachingMasterDb();
        console.log("Connection successful");

        // Set up change stream to listen for changes in the MasterDB collection
        const changeStream = MasterDB.watch();

        changeStream.on("change", async (change) => {
            console.log("Change detected:", change);

            // Get the affected document's ID and fetch the updated document
            const documentId = change.documentKey._id;
            const updatedDocument = await MasterDB.findOne({ _id: documentId });


            // Get old MasterDB
            const previousMasterDB = cache.get("masterDB");
            const previousDocument = previousMasterDB.find(item => item._id.equals(documentId));
            console.log("xxxxxxxxxxxx", previousDocument.vulnerability.length, updatedDocument.vulnerability.length)


            let email = null;
            if (previousDocument.vulnerability.length < updatedDocument.vulnerability.length) {
                email = `New Vulnerability Found: ${previousDocument.matchedSoftwareName} ${previousDocument.version}. New Vulnerability is ${updatedDocument.vulnerability.reverse()[0].cveID}`;
            }

            if (previousDocument.threats.length < updatedDocument.threats.length) {
                email = `New Exploitable Threat found in  ${previousDocument.matchedSoftwareName} ${previousDocument.version}. New threat is ${updatedDocument.threats.reverse()[0].cveID}`;
            }

            if (change.updateDescription["updatedFields"]["matchedSoftwareVersion"]) {
                email = `New Software Version Found: ${previousDocument.matchedSoftwareName} ${previousDocument.matchedSoftwareVersion}. New Vesion ${updatedDocument.matchedSoftwareVersion}`
            }
            // console.log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",updatedDocument.vulnerability.reverse()[0].cveID )


            console.log(email)
            // Get the company domains from the updated document
            const companyDomains = updatedDocument.companyDomain;

            // Find users whose company_domain matches the updated company domains
            const users = await User.find({ company_domain: { $in: companyDomains } });


            if (email) {

                // Send email to affected users
                for (const user of users) {
                    if (user.isNotificationOn) {

                        const userEmail = user.email;

                        const notification = await Notification.findOne({ email: userEmail });
                        

                        if (notification) {
                            const dummyNotification = notification.dummyNotification;
                            const updatedDummyNotification = [...dummyNotification, email];
                            await Notification.findOneAndUpdate({ email: user.email }, { dummyNotification: updatedDummyNotification }, { new: true });
                        }
                        else {
                            const newNotification = new Notification({
                                email: user.email,
                                notification: [],
                                dummyNotification: [email]
                            })
                            const notificationSend = await newNotification.save();
                            console.log("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", notificationSend)
                        }

                        const mailOptions = {
                            from: 'shafinahnam89@gmail.com',
                            to: user.email,
                            subject: 'MasterDB Update Notification',
                            html: `
                        <!DOCTYPE html>
                        <html lang="en">
                        <head>
                            <meta charset="UTF-8">
                            <meta name="viewport" content="width=device-width, initial-scale=1.0">
                            <style>
                                body {
                                    font-family: Arial, sans-serif;
                                    background-color: #f4f4f4;
                                    margin: 0;
                                    padding: 0;
                                    -webkit-font-smoothing: antialiased;
                                    -moz-osx-font-smoothing: grayscale;
                                    text-align: center;
                                }
                                .container {
                                    width: 60%;
                                    max-width: 600px;
                                    margin: 0 auto;
                                    background-color: #ffffff;
                                    padding: 20px;
                                    border-radius: 8px;
                                    box-shadow: 0px -1px 5px 10px rgba(217,204,204,0.48);
-webkit-box-shadow: 0px -1px 5px 10px rgba(217,204,204,0.48);
-moz-box-shadow: 0px -1px 5px 10px rgba(217,204,204,0.48);
text-align : center;
                                }
                                .header {
                                    padding-bottom: 20px;
                                }
                                .header img {
                                    width: 150px;
                                }
                                .content h1 {
                                    color: #333333;
                                }
                                .content p {
                                    color: #666666;
                                    line-height: 1.5;
                                }
                                    .button-container {
                                text-align: center;
                                margin: 20px 0;
                                display:flex;
                                justify-content: center;
                                align-items: center;
                            }
                           .button {
                                background-color: #007BFF;
                                color: #ffffff;
                                padding: 15px 25px;
                                text-decoration: none;
                                border-radius: 5px;
                                font-weight: bold;
                                border: none;
                                cursor: pointer;
                                display: inline-block;
                            }
                                .footer {
                                    padding-top: 20px;
                                    border-top: 1px solid #eeeeee;
                                    color: #999999;
                                }
                            </style>
                        </head>
                        <body>
                            <div class="container">
                                <div class="header">
                                    <img src="https://vuln-backup.vercel.app/assets/images/logo.png" alt="VulnApp Logo">
                                </div>
                                <div class="content">
                                   
                                <h1>Dear ${user.first_name} ${user.last_name},</h1>
                                    <p>${email}</p>
                                   
                                    <p>Please logon to vulnapp Vulnapp to review</p>
                                   
                                    <div class="button-container">
                                    <a href="http://www.vulnapp.com/login" class="button">Log In</a>
                                </div>
                                    <p>Thank you,</p>
                                    <p>The <b>VulnApp</b> Team</p>
                                </div>
                            </div>
                        </body>
                        </html>
                        `
                        };

                        transporter.sendMail(mailOptions, (error, info) => {
                            if (error) {
                                console.error('Error sending email:', error);
                            } else {
                                console.log('Email sent:', info.response);
                            }
                        })
                    }
                }
            }
            email = null;



            // Broadcast the change via Socket.io
            io.emit("masterdb-change", updatedDocument);

        });

        cache.del("masterDB");
        cachingMasterDb();
    })
    .catch(err => console.log(err));

// Listen on port 4000
server.listen(4000, () => {
    console.log("Server is working on port 4000");

    callApi();

    // // Schedule the API call to run every 24 hours using cron
    const job = cron.schedule('0 0 * * *', callApi, {
        scheduled: true // Job is scheduled and active
    });

    // // Start the cron job
    job.start();
});
