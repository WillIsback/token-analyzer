// ⚠️ DEMO FILE - Shows dangerous JavaScript patterns
// This file demonstrates security anti-patterns

// 🔴 BAD: Hardcoded secret
const API_KEY = "sk-abcdefgh1234567890xxxxxxxxxxxxxxxxxxxx";

// 🔴 BAD: Logging the secret
console.log("Using API_KEY:", API_KEY);

// 🔴 BAD: Including in debug output
console.debug("Debug info - API_KEY =", API_KEY);

// Using the secret (this is fine, but the above patterns are dangerous)
async function makeRequest() {
    const response = await fetch("https://api.example.com/data", {
        headers: {
            "Authorization": `Bearer ${API_KEY}`,
            "Content-Type": "application/json"
        }
    });
    return response.json();
}

// 🔴 BAD: Error logging with secret
try {
    await makeRequest();
} catch (error) {
    console.error("Failed with API_KEY:", API_KEY, error);
}
