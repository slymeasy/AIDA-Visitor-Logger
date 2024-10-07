// File: frontend/aidaTracker.js

(function() {
    // Configuration for AIDA stages
    const AIDA_STAGES = [
        { stage: 'Attention', min: 0, max: 30 },
        { stage: 'Interest', min: 31, max: 60 },
        { stage: 'Desire', min: 61, max: 120 },
        { stage: 'Action', min: 121, max: Infinity }
    ];

    // Function to determine the AIDA stage based on time spent
    function getAIDAStage(timeSpent) {
        for (let stage of AIDA_STAGES) {
            if (timeSpent >= stage.min && timeSpent <= stage.max) {
                return stage.stage;
            }
        }
        return 'Unknown';
    }

    // Function to get query parameter values
    function getQueryParam(param) {
        let urlParams = new URLSearchParams(window.location.search);
        return urlParams.get(param) || 'n/a';
    }

    // Start tracking time
    let startTime = Date.now();

    // Event listener to send data when the user leaves the page
    window.addEventListener('beforeunload', function() {
        let endTime = Date.now();
        let timeSpent = Math.floor((endTime - startTime) / 1000); // Convert milliseconds to seconds
        let aidaStage = getAIDAStage(timeSpent);
        let referrer = document.referrer || 'n/a';
        let keyword = getQueryParam('q'); // Adjust parameter name based on the search engine if needed
        let pageURL = window.location.href;

        let data = {
            time_spent: timeSpent,
            aida_stage: aidaStage,
            referrer: referrer,
            keyword: keyword,
            page_url: pageURL
        };

        // Send data to the backend using sendBeacon
        navigator.sendBeacon('/backend/track.php', JSON.stringify(data));
    });
})();
