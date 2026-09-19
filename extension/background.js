function sendScanMessage(tabId, url) {

    if (!url) {
        return;
    }

    if (
        url.startsWith("chrome://") ||
        url.startsWith("chrome-extension://") ||
        url.startsWith("edge://") ||
        url.startsWith("about:")
    ) {
        return;
    }

    chrome.tabs.sendMessage(
        tabId,
        {
            action: "scanPage",
            url: url
        }
    ).catch(function() {
        // Content script may not be ready yet.
    });
}


chrome.webNavigation.onCommitted.addListener(
    function(details) {

        if (details.frameId !== 0) {
            return;
        }

        sendScanMessage(
            details.tabId,
            details.url
        );
    }
);


chrome.webNavigation.onHistoryStateUpdated.addListener(
    function(details) {

        if (details.frameId !== 0) {
            return;
        }

        sendScanMessage(
            details.tabId,
            details.url
        );
    }
);


chrome.webNavigation.onReferenceFragmentUpdated.addListener(
    function(details) {

        if (details.frameId !== 0) {
            return;
        }

        sendScanMessage(
            details.tabId,
            details.url
        );
    }
);


chrome.tabs.onUpdated.addListener(
    function(tabId, changeInfo, tab) {

        if (changeInfo.status === "complete") {

            if (tab && tab.url) {
                sendScanMessage(
                    tabId,
                    tab.url
                );
            }
        }
    }
);