document.addEventListener("DOMContentLoaded", function () {

    const totalLinks = document.getElementById("totalLinks");
    const suspiciousLinks = document.getElementById("suspiciousLinks");
    const status = document.getElementById("status");
    const result = document.getElementById("result");
    const scanButton = document.getElementById("scanButton");

    // Local fallback check
    function localURLCheck(url) {
        try {
            const parsed = new URL(url);
            let score = 0;
            const reasons = [];

            if (parsed.protocol !== "https:") {
                score += 25;
                reasons.push("No HTTPS");
            }

            if (/^\d+\.\d+\.\d+\.\d+$/.test(parsed.hostname)) {
                score += 30;
                reasons.push("IP-based domain");
            }

            const suspiciousWords = [
                "verify",
                "login",
                "signin",
                "account",
                "password",
                "secure",
                "update",
                "confirm",
                "bank"
            ];

            if (
                suspiciousWords.some(function (word) {
                    return url.toLowerCase().includes(word);
                })
            ) {
                score += 20;
                reasons.push("Suspicious keyword");
            }

            if (url.includes("@")) {
                score += 20;
                reasons.push("@ symbol found");
            }

            if (parsed.hostname.split(".").length > 3) {
                score += 10;
                reasons.push("Many subdomains");
            }

            return {
                suspicious: score >= 30,
                score: Math.min(score, 100),
                reasons: reasons
            };

        } catch (error) {
            return {
                suspicious: false,
                score: 0,
                reasons: ["Invalid URL"]
            };
        }
    }


    // Flask + URL ML Model
    async function scanWithAI(url) {

        try {

            const response = await fetch(
                "http://127.0.0.1:5000/scan/url",
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
                throw new Error("API request failed");
            }

            const data = await response.json();

            return data;

        } catch (error) {

            console.log("PhishGuard API error:", error);

            return null;
        }
    }


    async function scanCurrentPage() {

        status.textContent = "🔄 Scanning...";
        result.textContent = "PhishGuard is analysing this page...";

        chrome.tabs.query(
            { active: true, currentWindow: true },
            async function (tabs) {

                if (!tabs || !tabs[0]) {
                    status.textContent = "❌ Unable to access page";
                    result.textContent = "No active tab found.";
                    return;
                }

                const currentURL = tabs[0].url || "";

                // Browser internal pages
                if (
                    currentURL.startsWith("chrome://") ||
                    currentURL.startsWith("chrome-extension://") ||
                    currentURL.startsWith("edge://") ||
                    currentURL.startsWith("about:")
                ) {
                    status.textContent = "⚠️ Page cannot be scanned";
                    result.textContent =
                        "Chrome internal pages cannot be analysed.";
                    totalLinks.textContent = "0";
                    suspiciousLinks.textContent = "0";
                    return;
                }


                // Ask content.js for links
                chrome.tabs.sendMessage(
                    tabs[0].id,
                    { type: "SCAN_PAGE" },
                    async function (response) {

                        let linkCount = 0;
                        let suspiciousCount = 0;

                        if (!chrome.runtime.lastError && response) {

                            linkCount =
                                response.totalLinks || 0;

                            suspiciousCount =
                                response.suspiciousLinks
                                    ? response.suspiciousLinks.length
                                    : 0;
                        }


                        // Local URL check
                        const localResult =
                            localURLCheck(currentURL);


                        // Flask ML check
                        const aiResult =
                            await scanWithAI(currentURL);


                        totalLinks.textContent =
                            linkCount + 1;


                        if (localResult.suspicious) {
                            suspiciousCount++;
                        }


                        let finalScore =
                            localResult.score;

                        let prediction =
                            localResult.suspicious
                                ? "suspicious"
                                : "safe";

                        let aiMessage = "";


                        // Use ML result when Flask is available
                        if (aiResult) {

                            finalScore =
                                Math.max(
                                    finalScore,
                                    Number(aiResult.risk_score) || 0
                                );

                            prediction =
                                aiResult.prediction;

                            aiMessage =
                                "\n\n🤖 AI Model: " +
                                prediction +
                                "\nAI Risk Score: " +
                                aiResult.risk_score +
                                "/100";
                        }


                        if (
                            prediction === "suspicious" ||
                            finalScore >= 30
                        ) {

                            suspiciousCount++;

                            status.textContent =
                                "⚠️ Suspicious URL Detected";

                            result.textContent =
                                "Risk Score: " +
                                finalScore +
                                "/100\n\n" +
                                "Reasons: " +
                                localResult.reasons.join(", ") +
                                aiMessage;

                        } else {

                            status.textContent =
                                "✅ Page Looks Safe";

                            result.textContent =
                                "No suspicious URL detected." +
                                aiMessage;
                        }


                        suspiciousLinks.textContent =
                            suspiciousCount;
                    }
                );
            }
        );
    }


    if (scanButton) {
        scanButton.addEventListener(
            "click",
            scanCurrentPage
        );
    }


    // Initial scan
    scanCurrentPage();

});