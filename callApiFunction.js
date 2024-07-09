const axios = require('axios');
const MasterDB = require("./schemas/masterDBSchema");


const {
    GoogleGenerativeAI,
    HarmCategory,
    HarmBlockThreshold,
} = require("@google/generative-ai");




const apiKey = "AIzaSyCIwjObmm5hw2ANvYII9g-LkjC_HZDGPFI";
const genAI = new GoogleGenerativeAI(apiKey);


const model = genAI.getGenerativeModel({
    model: "gemini-1.5-flash",
});

const generationConfig = {
    temperature: 1,
    topP: 0.95,
    topK: 64,
    maxOutputTokens: 8192,
    responseMimeType: "text/plain",
};

const safetySettings = [
    {
        category: HarmCategory.HARM_CATEGORY_HARASSMENT,
        threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
        category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
        threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
        category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
        threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
    {
        category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
        threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
    },
];


async function run(input) {
    // TODO Make these files available on the local file system
    // You may need to update the file paths

    const chatSession = model.startChat({
        generationConfig,
        // safetySettings: Adjust safety settings
        // See https://ai.google.dev/gemini-api/docs/safety-settings
        history: [
            {
                role: "user",
                parts: [
                    { text: "what id the vendor name of winrar?\n" },
                ],
            },
            {
                role: "model",
                parts: [
                    { text: "The vendor name for WinRAR is **Win.rar GmbH**. \n" },
                ],
            },
            {
                role: "user",
                parts: [
                    { text: "isnt it rarlab?" },
                ],
            },
            {
                role: "model",
                parts: [
                    { text: "You are absolutely right! My apologies for the mistake. \n\nThe vendor name for WinRAR is indeed **RARLab**.  \n\nI am still under development and learning to provide accurate information. Thanks for pointing out the error! \n" },
                ],
            },
            {
                role: "user",
                parts: [
                    { text: "what is the vendor name of uc browser" },
                ],
            },
            {
                role: "model",
                parts: [
                    { text: "The vendor name for UC Browser is **UCWeb**. \n\nUCWeb is a subsidiary of Alibaba Group, and they are the developers and distributors of the popular mobile browser, UC Browser. \n" },
                ],
            },
            {
                role: "user",
                parts: [
                    { text: "i just only need vendor name in one word. please return only vendor name in only one word." },
                    { text: "what is the vendor name of google chrome" },
                ],
            },
            {
                role: "model",
                parts: [
                    { text: "Google \n" },
                ],
            },
            {
                role: "user",
                parts: [
                    { text: "what is the vendor name of winrar" },
                ],
            },
            {
                role: "model",
                parts: [
                    { text: "RARLab \n" },
                ],
            },
            {
                role: "user",
                parts: [
                    { text: "always return 7-zip as the vendor name of 7-zip. \n" },
                ],
            }
        ],
    });

    try {
        const result = await chatSession.sendMessage(input);
        return (result.response.text());
    } catch (error) {
        console.log(error)
    }
}


let isRunning = false;

async function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function delayForGoogleGenerativeAi(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// async function run(input) {
//     // Mock AI response for demonstration purposes
//     const aiResponses = {
//         "winrar": "RARLab",
//         "uc browser": "UCWeb",
//         "google chrome": "Google",
//         "7-zip": "7-zip"
//         // Add more mappings as needed
//     };

//     return aiResponses[input.toLowerCase()] || null; // Return null if vendor name is not found
// }

async function callApi() {
    if (isRunning) {
        console.log('Previous instance still running, skipping this execution.');
        return;
    }

    isRunning = true;
    try {
        console.log("API call started at", new Date());
        const data = await MasterDB.find();
        const softwareDataWithActiveStatus = data.filter(item => item.status === "active");

        for (let item of softwareDataWithActiveStatus) {
            if (item.cveRetrieved) {
                console.log(`Skipping CVE collection for ${item.matchedSoftwareName} as CVEs have already been retrieved.`);
                continue;
            }

            const temporaryName = item.matchedSoftwareName.toLowerCase();
            console.log(item.dummyVulnerability);
            const dummyVulnWithManualSource = item.dummyVulnerability.filter(each => each.source === "Manual");
            let extractedTemporaryName = temporaryName.replace(/\([^)]*\)/, '').replace(/_+$/, '');

            let vendorName = null;
            while (!vendorName) {
                vendorName = await run(temporaryName);
                try {
                    if (!vendorName) {
                        console.log(`Vendor name not found for ${temporaryName}, retrying...`);
                        await delay(2000); // Delay before retrying
                    }
                } catch (error) {
                    await delay(10000);
                }
            }

            console.log("This is the vendor name:", vendorName);
            let cpaNameArray = [];
            let vulnerability = [];

            try {
                const responseWithCPAString = await axios.get(`https://services.nvd.nist.gov/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:*:${vendorName.toLowerCase()}`, {
                    headers: {
                        'apiKey': '5e47196f-75f1-4391-9ba5-088678c5ab25'
                    }
                });
                const dataWithCPAString = responseWithCPAString.data?.products || [];

                for (const iterator of dataWithCPAString) {
                    if (iterator?.cpe?.titles[0].title.toLowerCase().includes(extractedTemporaryName) && iterator?.cpe?.cpeName.includes(item.version)) {
                        cpaNameArray.push(iterator);
                    }
                }
                

                if (cpaNameArray.length === 0) {
                    console.log(`No CPA names found for vendor: ${vendorName} and software: ${extractedTemporaryName}`);
                    continue; // Skip to the next iteration if no CPA names are found
                }

                for (const cpaItem of cpaNameArray) {
                    try {
                        const responseWithCVE = await axios.get(`https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpaItem?.cpe?.cpeName}`, {
                            headers: {
                                'apiKey': '5e47196f-75f1-4391-9ba5-088678c5ab25'
                            }
                        });
                        const dataWithCVE = responseWithCVE.data;
                        let arr = dataWithCVE?.vulnerabilities || [];
                        vulnerability.push(...arr);
                        
                    } catch (error) {
                        console.log(`Error fetching CVEs for ${cpaItem?.cpe?.cpeName}:`, error);
                        await delay(20000); // Retry delay
                    }
                }
                

                if (vulnerability.length > 0) {
                    item.cveRetrieved = true; // Mark the item as having CVEs retrieved

                    const uniqueVulnerabilities = vulnerability.filter((vuln, index, self) =>
                        index === self.findIndex((t) => t.cve.id === vuln.cve.id)
                    );

                    let extractedInformationOfVulnerability = [];
                    for (let i = 0; i < uniqueVulnerabilities.length; i++) {
                        let vulnObj = {};
                        let cve = uniqueVulnerabilities[i].cve;

                        vulnObj.cveID = cve?.id;
                        vulnObj.publishedDate = cve?.published;
                        vulnObj.lastModified = cve?.lastModified;

                        if (cve?.descriptions && cve?.descriptions.length > 0) {
                            vulnObj.description = cve?.descriptions[0].value;
                        } else {
                            vulnObj.description = "No description available";
                        }

                        let baseSeverity = null;
                        if (cve?.metrics) {
                            if (cve?.metrics?.cvssMetricV30 && cve?.metrics?.cvssMetricV30?.length > 0) {
                                baseSeverity = cve?.metrics?.cvssMetricV30[0]?.cvssData?.baseSeverity;
                            } else if (cve?.metrics?.cvssMetricV31 && cve?.metrics?.cvssMetricV31?.length > 0) {
                                baseSeverity = cve?.metrics?.cvssMetricV31[0]?.cvssData?.baseSeverity;
                            }
                        }

                        vulnObj.baseSeverity = baseSeverity || "Severity not available";
                        vulnObj.references = cve.references.map(item => item.url) || [];
                        vulnObj.source = "NVD";
                        extractedInformationOfVulnerability.push(vulnObj);
                    }

                    if (item.deletedVulnerability.length > 0) {
                        const { deletedVulnerability } = item;
                        const { dummyVulnerability } = item;

                        extractedInformationOfVulnerability = extractedInformationOfVulnerability.filter(
                            extracted => !deletedVulnerability.some(deleted => deleted.cveID === extracted.cveID)
                        );

                        const updatedDummyVulnerability = [...dummyVulnerability, ...extractedInformationOfVulnerability];

                        const finalDummyVulnerability = updatedDummyVulnerability.filter((vuln, index, self) =>
                            index === self.findIndex((t) => t.cveID === vuln.cveID)
                        );

                        const update = await MasterDB.findOneAndUpdate({ _id: item.id }, { dummyVulnerability: finalDummyVulnerability, cveRetrieved: true }, { new: true });

                        if (!update) {
                            console.log(`Item not found: ${item.id}`);
                        } else {
                            console.log(`Updated item: ${item.id} ---- ${item.program}`);
                        }
                    } else {
                        const updatedDummyVuln = [...dummyVulnWithManualSource, ...extractedInformationOfVulnerability];
                        const update = await MasterDB.findOneAndUpdate({ _id: item.id }, { dummyVulnerability: updatedDummyVuln, cveRetrieved: true }, { new: true });

                        if (!update) {
                            console.log(`Item not found: ${item.id}`);
                        } else {
                            console.log(`Updated item: ${item.id} ---- ${item.program}`);
                        }
                    }
                } else {
                    console.log(`No vulnerabilities found for ${item.matchedSoftwareName}`);
                }
            } catch (error) {
                console.log(`Error processing vendor ${vendorName}:`, error);
            }

            await delayForGoogleGenerativeAi(100);
        }
    } catch (error) {
        console.error('Error calling API:', error);
    } finally {
        isRunning = false;
        console.log("stop");
    }
}


module.exports = {
    callApi
};






