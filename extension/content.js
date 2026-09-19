(function () {

    let alreadyWarned = false;

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
        "urgent"
    ];

    function checkURL(url) {

        try {

            const u = new URL(url);

            let score = 0;
            let reasons = [];

            if (u.protocol !== "https:") {
                score += 40;
                reasons.push("No HTTPS");
            }

            if (/^\d+\.\d+\.\d+\.\d+$/.test(u.hostname)) {
                score += 30;
                reasons.push("IP-based domain");
            }

            if (
                suspiciousWords.some(function (word) {
                    return url.toLowerCase().includes(word);
                })
            ) {
                score += 25;
                reasons.push("Suspicious keyword");
            }

            if (url.includes("@")) {
                score += 25;
                reasons.push("@ symbol found");
            }

            if (u.hostname.split(".").length > 3) {
                score += 20;
                reasons.push("Many subdomains");
            }

            return {
                suspicious: score >= 30,
                score: Math.min(score, 100),
                reasons: reasons
            };

        } catch {
            return {
                suspicious: false,
                score: 0,
                reasons: []
            };
        }
    }


    function showWarning(result, url) {

        if (alreadyWarned) return;

        alreadyWarned = true;

        const overlay = document.createElement("div");

        overlay.style.cssText = `
            position:fixed;
            inset:0;
            background:rgba(0,0,0,0.60);
            z-index:2147483647;
            display:flex;
            align-items:center;
            justify-content:center;
        `;

        const box = document.createElement("div");

        box.style.cssText = `
            width:430px;
            max-width:90%;
            background:white;
            padding:30px;
            border-radius:18px;
            text-align:center;
            font-family:Arial,sans-serif;
            box-shadow:0 20px 70px rgba(0,0,0,0.5);
            border:3px solid #ef4444;
        `;

        box.innerHTML = `
            <div style="font-size:50px;">⚠️</div>

            <h2 style="color:#dc2626;margin:10px 0;">
                PhishGuard Warning
            </h2>

            <h3 style="margin-bottom:15px;">
                Suspicious website detected!
            </h3>

            <div style="
                display:inline-block;
                padding:8px 15px;
                background:#fee2e2;
                color:#b91c1c;
                border-radius:8px;
                font-weight:bold;
                margin-bottom:15px;
            ">
                Risk Score: ${result.score}/100
            </div>

            <div style="
                background:#f3f4f6;
                padding:10px;
                border-radius:8px;
                font-size:12px;
                word-break:break-all;
                margin-bottom:15px;
            ">
                ${url}
            </div>

            <div style="
                text-align:left;
                background:#fff7ed;
                padding:15px;
                border-radius:8px;
                margin-bottom:20px;
            ">
                <b>Reasons:</b><br><br>
                ${result.reasons.join("<br>")}
            </div>

            <button id="pgClose" style="
                padding:12px 25px;
                border:0;
                border-radius:8px;
                background:#2563eb;
                color:white;
                font-weight:bold;
                cursor:pointer;
            ">
                Close Warning
            </button>
        `;

        overlay.appendChild(box);
        document.body.appendChild(overlay);

        document.getElementById("pgClose").onclick = function () {
            overlay.remove();
        };
    }


    function scan() {

        if (alreadyWarned) return;

        const currentURL = window.location.href;

        if (
            currentURL.startsWith("chrome://") ||
            currentURL.startsWith("chrome-extension://") ||
            currentURL.startsWith("edge://") ||
            currentURL.startsWith("about:")
        ) {
            return;
        }

        // Check current page URL
        const pageResult = checkURL(currentURL);

        if (pageResult.suspicious) {
            showWarning(pageResult, currentURL);
            return;
        }

        // Check links inside the page
        const links = document.querySelectorAll("a[href]");

        for (const link of links) {

            const href = link.href;

            const result = checkURL(href);

            if (result.suspicious) {

                showWarning(result, href);

                return;
            }
        }
    }


    // Run after page loads
    setTimeout(scan, 1000);

    // Check again for dynamically loaded links
    setInterval(scan, 2000);

})();