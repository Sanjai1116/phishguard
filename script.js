let lastResult = null;
let lastScanInput = "";
let lastScanType = "";

const suspiciousWords = [
    "verify",
    "verification",
    "login",
    "signin",
    "account",
    "password",
    "secure",
    "update",
    "confirm",
    "bank",
    "otp",
    "urgent",
    "click"
];


// =========================
// URL CHECK
// =========================

function checkURL(url) {

    let score = 0;
    let reasons = [];

    try {

        const parsed = new URL(url);

        if (parsed.protocol !== "https:") {
            score += 40;
            reasons.push("No HTTPS");
        }

        if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) {
            score += 30;
            reasons.push("IP-based domain");
        }

        const foundWords = suspiciousWords.filter(function(word) {
            return url.toLowerCase().includes(word);
        });

        if (foundWords.length > 0) {
            score += 25;
            reasons.push("Suspicious keyword");
        }

        if (url.includes("@")) {
            score += 25;
            reasons.push("@ symbol found");
        }

        if (parsed.hostname.split(".").length > 3) {
            score += 20;
            reasons.push("Many subdomains");
        }

        const hostname = parsed.hostname.toLowerCase();

        if (
            hostname.includes("verification") ||
            hostname.includes("verify") ||
            hostname.includes("secure") ||
            hostname.includes("login") ||
            hostname.includes("account")
        ) {
            score += 20;
            reasons.push("Suspicious hostname");
        }

    } catch (error) {

        score = 20;
        reasons.push("Invalid URL format");
    }

    return {
        suspicious: score >= 30,
        score: Math.min(score, 100),
        reasons: reasons
    };
}


// =========================
// SCAN URL - FLASK AI
// =========================

async function scanURL() {

    const urlInput =
        document.getElementById("urlInput");

    const resultStatus =
        document.getElementById("resultStatus");

    const riskScore =
        document.getElementById("riskScore");

    const reasons =
        document.getElementById("reasons");


    const url =
        urlInput.value.trim();


    if (!url) {

        alert("Please enter a URL.");

        return;
    }


    resultStatus.textContent =
        "🔄 Scanning...";

    riskScore.textContent =
        "Analyzing...";

    reasons.innerHTML =
        "PhishGuard AI is analysing the URL...";


    try {

        const response =
            await fetch(
                "/api/scan/url",
                {
                    method: "POST",

                    headers: {
                        "Content-Type": "application/json"
                    },

                    body: JSON.stringify({
                        url: url
                    })
                }
            );


        if (!response.ok) {

            throw new Error(
                "API request failed"
            );
        }


        const data =
            await response.json();


        lastScanInput =
            url;

        lastScanType =
            "URL";


        lastResult = {

            suspicious:
                data.prediction === "suspicious",

            score:
                Number(data.risk_score) || 0,

            reasons:
                data.prediction === "suspicious"
                    ? [
                        "AI model detected this URL as suspicious."
                    ]
                    : [
                        "AI model did not detect strong suspicious signals."
                    ]
        };


        if (
            data.prediction === "suspicious"
        ) {

            resultStatus.textContent =
                "🔴 Suspicious URL";

        } else {

            resultStatus.textContent =
                "🟢 URL Looks Safe";
        }


        riskScore.textContent =
            Number(data.risk_score).toFixed(2) +
            "/100";


        reasons.innerHTML =
            lastResult.reasons.join("<br>");


        saveScanHistory(
            lastScanType,
            lastScanInput,
            lastResult
        );
        const reportButton = document.getElementById("reportButton");

if (reportButton) {
    reportButton.style.display =
        lastResult.suspicious ? "inline-block" : "none";
}

    }

    catch (error) {

        console.error(
            "PhishGuard API error:",
            error
        );


        resultStatus.textContent =
            "❌ Scan Failed";

        riskScore.textContent =
            "--";

        reasons.innerHTML =
            "Unable to connect to PhishGuard AI server.<br>" +
            "Make sure the Flask API is running.";
    }
}


// =========================
// SCAN MESSAGE
// =========================

async function scanMessage() {

    const input = document.getElementById("messageInput");
    const message = input.value.trim();

    if (!message) {
        alert("Please paste an email or message.");
        return;
    }

    try {

        const response = await fetch(
            "/api/scan/text",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    text: message
                })
            }
        );

        if (!response.ok) {
            throw new Error("API request failed");
        }

        const data = await response.json();

        lastResult = {
            suspicious: data.prediction === "suspicious",
            score: Number(data.risk_score) || 0,
            reasons: data.reasons || []
        };

        lastScanInput = message;
        lastScanType = "Message";

        showResult(lastResult);

        saveScanHistory(
            lastScanType,
            lastScanInput,
            lastResult
        );

    } catch (error) {

        console.error("PhishGuard Text API Error:", error);

        alert(
            "Unable to connect to PhishGuard AI. Make sure the Flask API is running."
        );
    }
}


// =========================
// SCAN EMAIL ID
// =========================

async function scanEmail() {

    const input = document.getElementById("emailInput");
    const email = input.value.trim();

    if (!email) {
        alert("Please enter a sender email.");
        return;
    }

    try {

        const response = await fetch(
            "/api/scan/text",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    text: email
                })
            }
        );

        if (!response.ok) {
            throw new Error("API request failed");
        }

        const data = await response.json();

        lastResult = {
            suspicious: data.prediction === "suspicious",
            score: Number(data.risk_score) || 0,
            reasons: data.reasons || []
        };

        lastScanInput = email;
        lastScanType = "Email";

        showResult(lastResult);

        saveScanHistory(
            lastScanType,
            lastScanInput,
            lastResult
        );

    } catch (error) {

        console.error("PhishGuard Email API Error:", error);

        alert(
            "Unable to connect to PhishGuard AI. Make sure the Flask API is running."
        );
    }
}


// =========================
// SHOW RESULT
// =========================

function showResult(result) {

    const resultStatus =
        document.getElementById(
            "resultStatus"
        );

    const riskScore =
        document.getElementById(
            "riskScore"
        );

    const reasons =
        document.getElementById(
            "reasons"
        );

    const reportButton =
        document.getElementById(
            "reportButton"
        );


    if (result.suspicious) {

        resultStatus.innerHTML =
            "🔴 Suspicious";

        riskScore.innerHTML =
            "Risk Score: " +
            result.score +
            "/100";

        reasons.innerHTML =
            "<b>Reasons:</b><br>" +
            result.reasons.join("<br>");


        if (reportButton) {

            reportButton.style.display =
                "inline-block";
        }

    } else {

        resultStatus.innerHTML =
            "🟢 Safe";

        riskScore.innerHTML =
            "Risk Score: " +
            result.score +
            "/100";


        reasons.innerHTML =
            result.reasons.length > 0
                ? "<b>Notes:</b><br>" +
                  result.reasons.join("<br>")
                : "No suspicious signs detected.";


        if (reportButton) {

            reportButton.style.display =
                "none";
        }
    }
}


// =========================
// GENERATE REPORT
// =========================

function generateReport() {

    if (
        !lastResult ||
        !lastResult.suspicious
    ) {

        return;
    }


    const reportText =
        "PhishGuard Suspicious Activity Report\n\n" +

        "Scan Type: " +
        lastScanType +

        "\n\nDetected Input:\n" +
        lastScanInput +

        "\n\nRisk Score: " +
        lastResult.score +
        "/100" +

        "\n\nReasons:\n" +
        lastResult.reasons.join("\n") +

        "\n\nStatus: Suspicious";


    document.getElementById(
        "reportContent"
    ).innerText =
        reportText;


    document.getElementById(
        "sendReportButton"
    ).style.display =
        "inline-block";


    document.getElementById(
        "officialComplaintButton"
    ).style.display =
        "none";


    document.getElementById(
        "report"
    ).scrollIntoView({
        behavior: "smooth"
    });
}


// =========================
// SEND REPORT
// =========================

function sendReport() {

    if (
        !lastResult ||
        !lastResult.suspicious
    ) {

        return;
    }


    const reportText =
        document.getElementById(
            "reportContent"
        ).innerText;


    const report = {

        id:
            Date.now(),

        type:
            lastScanType,

        input:
            lastScanInput,

        suspicious:
            lastResult.suspicious,

        score:
            lastResult.score,

        reasons:
            lastResult.reasons,

        date:
            new Date().toLocaleString(),

        reportText:
            reportText
    };


    let reports =
        JSON.parse(
            localStorage.getItem(
                "phishguardReportHistory"
            )
        ) || [];


    reports.unshift(
        report
    );


    localStorage.setItem(
        "phishguardReportHistory",
        JSON.stringify(reports)
    );


    displayReportHistory();


    document.getElementById(
        "officialComplaintButton"
    ).style.display =
        "inline-block";


    alert(
        "🚨 Report sent successfully!\n\n" +
        "The report has been added to Report History."
    );


    document.getElementById(
        "report-history"
    ).scrollIntoView({
        behavior: "smooth"
    });
}


// =========================
// OPEN OFFICIAL COMPLAINT
// =========================

function openOfficialComplaint() {

    window.open(
        "https://www.cybercrime.gov.in/",
        "_blank"
    );
}


// =========================
// SAVE SCAN HISTORY
// =========================

function saveScanHistory(
    type,
    input,
    result
) {

    if (!result) {

        console.error(
            "Cannot save history: result is missing."
        );

        return;
    }


    let history =
        JSON.parse(
            localStorage.getItem(
                "phishguardScanHistory"
            )
        ) || [];


    history.unshift({

        type:
            type,

        input:
            input,

        suspicious:
            result.suspicious,

        score:
            result.score,

        reasons:
            result.reasons,

        date:
            new Date().toLocaleString()
    });


    localStorage.setItem(
        "phishguardScanHistory",
        JSON.stringify(history)
    );


    displayScanHistory();
}


// =========================
// DISPLAY SCAN HISTORY
// =========================

function displayScanHistory() {

    const historyList =
        document.getElementById(
            "historyList"
        );


    if (!historyList) {

        return;
    }


    const history =
        JSON.parse(
            localStorage.getItem(
                "phishguardScanHistory"
            )
        ) || [];


    if (
        history.length === 0
    ) {

        historyList.innerHTML =
            "No scan history available.";

        return;
    }


    let output = "";


    history.forEach(
        function(item) {

            const status =
                item.suspicious
                    ? "🔴 Suspicious"
                    : "🟢 Safe";


            output +=

                '<div class="history-item">' +

                "<strong>" +
                item.type +
                " - " +
                status +
                "</strong>" +

                "<p>Risk Score: " +
                item.score +
                "/100</p>" +

                "<p>" +
                escapeHTML(
                    String(item.input || "")
                        .substring(0, 150)
                ) +
                "</p>" +

                "<small>" +
                item.date +
                "</small>" +

                "</div>";
        }
    );


    historyList.innerHTML =
        output;
}


// =========================
// DISPLAY REPORT HISTORY
// =========================

function displayReportHistory() {

    const reportHistoryList =
        document.getElementById(
            "reportHistoryList"
        );


    if (!reportHistoryList) {

        return;
    }


    const reports =
        JSON.parse(
            localStorage.getItem(
                "phishguardReportHistory"
            )
        ) || [];


    if (
        reports.length === 0
    ) {

        reportHistoryList.innerHTML =
            "No report history available.";

        return;
    }


    let output = "";


    reports.forEach(
        function(report) {

            output +=

                '<div class="history-item">' +

                "<strong>🚨 " +
                report.type +
                " - Report Sent</strong>" +

                "<p>Risk Score: " +
                report.score +
                "/100</p>" +

                "<p>" +
                escapeHTML(
                    String(report.input || "")
                        .substring(0, 150)
                ) +
                "</p>" +

                "<small>" +
                report.date +
                "</small>" +

                "<br>" +

                '<button onclick="viewReport(' +
                report.id +
                ')">' +

                "👁️ View Report" +

                "</button>" +

                "</div>";
        }
    );


    reportHistoryList.innerHTML =
        output;
}


// =========================
// VIEW REPORT
// =========================

function viewReport(reportId) {

    const reports =
        JSON.parse(
            localStorage.getItem(
                "phishguardReportHistory"
            )
        ) || [];


    const report =
        reports.find(
            function(item) {

                return item.id === reportId;

            }
        );


    if (!report) {

        return;
    }


    const viewer =
        document.getElementById(
            "reportViewer"
        );


    if (!viewer) {

        return;
    }


    viewer.innerHTML =

        '<div class="report-viewer-card">' +

        "<h3>📄 Report Details</h3>" +

        "<pre>" +
        escapeHTML(
            report.reportText
        ) +
        "</pre>" +

        "</div>";


    viewer.scrollIntoView({
        behavior: "smooth"
    });
}


// =========================
// CLEAR SCAN HISTORY
// =========================

function clearScanHistory() {

    localStorage.removeItem(
        "phishguardScanHistory"
    );


    displayScanHistory();


    alert(
        "🗑️ Scan History cleared successfully."
    );
}


// =========================
// CLEAR REPORT HISTORY
// =========================

function clearReportHistory() {

    localStorage.removeItem(
        "phishguardReportHistory"
    );


    displayReportHistory();


    const viewer =
        document.getElementById(
            "reportViewer"
        );


    if (viewer) {

        viewer.innerHTML =
            "";
    }


    alert(
        "🗑️ Report History cleared successfully."
    );
}


// =========================
// BASIC HTML ESCAPE
// =========================

function escapeHTML(text) {

    const div =
        document.createElement(
            "div"
        );


    div.textContent =
        text;


    return div.innerHTML;
}


// =========================
// PAGE LOAD
// =========================

document.addEventListener(
    "DOMContentLoaded",
    function() {

        displayScanHistory();

        displayReportHistory();


        const scanButton =
            document.getElementById(
                "scanURLButton"
            );


        if (scanButton) {

            scanButton.addEventListener(
                "click",
                scanURL
            );
        }


        const messageButton =
            document.getElementById(
                "scanMessageButton"
            );


        if (messageButton) {

            messageButton.addEventListener(
                "click",
                scanMessage
            );
        }


        const emailButton =
            document.getElementById(
                "scanEmailButton"
            );


        if (emailButton) {

            emailButton.addEventListener(
                "click",
                scanEmail
            );
        }

    }
);
async function scanWebpage() {

    console.log("scanWebpage function started");

    const url =
        document.getElementById("webpageURLInput").value.trim();

    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    const resultStatus =
        document.getElementById("resultStatus");

    const riskScore =
        document.getElementById("riskScore");

    const reasons =
        document.getElementById("reasons");

    resultStatus.textContent = "🔄 Scanning webpage...";
    riskScore.textContent = "Analyzing...";
    reasons.innerHTML = "PhishGuard AI is analysing...";

    try {

        const response = await fetch(
            "/api/scan/webpage",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: url
                })
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.message || "Scan failed"
            );
        }

        const result = data.result;

        resultStatus.textContent =
            "🛡️ " + result.risk_level + " Risk";

        riskScore.textContent =
            result.risk_score + "/100";

        reasons.innerHTML =
            (result.reasons || [])
                .map(reason => "• " + reason)
                .join("<br>");
                       lastScanInput = url;
lastScanType = "Webpage";

lastResult = {
    suspicious: result.risk_level !== "Low",
    score: Number(result.risk_score) || 0,
    reasons: result.reasons || []
};

saveScanHistory(
    lastScanType,
    lastScanInput,
    lastResult
);
    } catch (error) {

        console.error(
            "Webpage Scanner Error:",
            error
        );

        resultStatus.textContent =
            "❌ Scan Failed";

        riskScore.textContent =
            "--";

        reasons.innerHTML =
            error.message;
    }
}


document.addEventListener(
    "DOMContentLoaded",
    function () {

        const button =
            document.getElementById(
                "scanWebpageButton"
            );

        if (button) {
            button.addEventListener(
                "click",
                scanWebpage
            );
        }

    }
);
async function scanAPK() {

    const fileInput = document.getElementById("apkFileInput");
    const file = fileInput.files[0];

    if (!file) {
        alert("Please select an APK file.");
        return;
    }

    const resultStatus =
        document.getElementById("resultStatus");

    const riskScore =
        document.getElementById("riskScore");

    const reasons =
        document.getElementById("reasons");

    resultStatus.textContent = "🔄 Scanning APK...";
    riskScore.textContent = "Analyzing...";
    reasons.innerHTML =
        "PhishGuard is analysing the APK safely...";

    try {

        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch(
            "/api/scan/apk",
            {
                method: "POST",
                body: formData
            }
        );

        const data = await response.json();

        if (!response.ok || data.status !== "success") {
            throw new Error(
                data.message || "APK scan failed."
            );
        }

        const result = data.result;

        resultStatus.textContent =
            "🛡️ " + result.risk_level + " Risk";

        riskScore.textContent =
            result.risk_score + "/100";

        reasons.innerHTML =
            (result.reasons || [])
                .map(reason => "• " + reason)
                .join("<br>");

    } catch (error) {

        console.error(
            "APK Scanner Error:",
            error
        );

        resultStatus.textContent =
            "❌ APK Scan Failed";

        riskScore.textContent = "--";

        reasons.innerHTML =
            error.message;
    }
}


document.addEventListener(
    "DOMContentLoaded",
    function () {

        const apkButton =
            document.getElementById("scanAPKButton");

        if (apkButton) {
            apkButton.addEventListener(
                "click",
                scanAPK
            );
        }

    }
);
async function scanAPKURL() {

    const url =
        document.getElementById("apkURLInput").value.trim();

    if (!url) {
        alert("Please enter an APK download link.");
        return;
    }

    const resultStatus =
        document.getElementById("resultStatus");

    const riskScore =
        document.getElementById("riskScore");

    const reasons =
        document.getElementById("reasons");

    resultStatus.textContent = "🔄 Scanning APK link...";
    riskScore.textContent = "Analyzing...";
    reasons.innerHTML =
        "PhishGuard is safely analysing the APK...";

    try {

        const response = await fetch(
            "/api/scan/apk-url",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    url: url
                })
            }
        );

        const data = await response.json();

        if (!response.ok || data.status !== "success") {
            throw new Error(
                data.message || "APK link scan failed."
            );
        }

        const result = data.result;

        resultStatus.textContent =
            "🛡️ " + result.risk_level + " Risk";

        riskScore.textContent =
            result.risk_score + "/100";

        reasons.innerHTML =
            (result.reasons || [])
                .map(reason => "• " + reason)
                .join("<br>");

    } catch (error) {

        console.error(
            "APK Link Scanner Error:",
            error
        );

        resultStatus.textContent =
            "❌ APK Link Scan Failed";

        riskScore.textContent = "--";

        reasons.innerHTML =
            error.message;
    }
}


document.addEventListener(
    "DOMContentLoaded",
    function () {

        const apkURLButton =
            document.getElementById(
                "scanAPKURLButton"
            );

        if (apkURLButton) {
            apkURLButton.addEventListener(
                "click",
                scanAPKURL
            );
        }

    }
);
document.addEventListener("DOMContentLoaded", function () {

    const scanWebpageButton =
        document.getElementById("scanWebpageButton");

    if (scanWebpageButton) {
        scanWebpageButton.addEventListener(
            "click",
            scanWebpage
        );
    }

});