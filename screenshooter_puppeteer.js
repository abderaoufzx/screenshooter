const puppeteer = require('puppeteer');
const fs = require('fs');

async function takeScreenshot(params) {
    const browser = await puppeteer.launch({
        executablePath: process.env.RENDERER_BINARY || undefined,
        headless: true,
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-gpu',
            '--ignore-certificate-errors',
            '--disable-web-security'
        ],
        ignoreHTTPSErrors: true
    });
    const page = await browser.newPage();

    try {
        const url = params.url_capture;
        const outputFile = params.output_file;
        const [width, height] = params.window_size.split(',').map(Number);
        const timeout = Number(params.timeout) * 1000;

        await page.setViewport({ width, height });
        await page.setExtraHTTPHeaders(params.headers || {});
        if (params.http_username && params.http_password) {
            await page.authenticate({
                username: params.http_username,
                password: params.http_password
            });
        }

        // Attempt to navigate, but continue even if it fails
        let response = null;
        try {
            response = await page.goto(url, { waitUntil: 'networkidle2', timeout });
        } catch (navError) {
            console.warn(`Navigation failed for ${url}: ${navError.message}. Attempting to capture screenshot anyway.`);
        }

        const status = response ? response.status() : null;
        const headers = response ? await response.headers() : {};

        // Attempt to get page title, fallback to "Unknown" on error
        let title = "Unknown";
        try {
            title = await page.title();
        } catch (titleError) {
            console.warn(`Failed to retrieve title for ${url}: ${titleError.message}`);
        }

        // Capture screenshot regardless of navigation or title success
        await page.screenshot({ path: outputFile });

        const metadata = {
            url,
            screenshot: outputFile,
            status,
            headers,
            title,
            timestamp: new Date().toISOString(),
            error: response ? null : 'Navigation failed, screenshot captured'
        };
        fs.writeFileSync(outputFile.replace(/\.[^/.]+$/, '.json'), JSON.stringify(metadata, null, 2));
    } catch (error) {
        console.error(`Critical error capturing ${params.url_capture}: ${error.stack}`);
        const metadata = {
            url: params.url_capture,
            screenshot: params.output_file,
            status: null,
            headers: {},
            title: null,
            timestamp: new Date().toISOString(),
            error: error.message
        };
        fs.writeFileSync(params.output_file.replace(/\.[^/.]+$/, '.json'), JSON.stringify(metadata, null, 2));
        await browser.close();
        process.exit(1);
    }

    await browser.newPage()
    await browser.close();
}

const params = {};
process.argv.forEach(arg => {
    const [key, value] = arg.split('=');
    if (key && value) {
        if (key === 'header') {
            params.headers = params.headers || {};
            const [hKey, hValue] = value.split(': ');
            params.headers[hKey] = hValue;
        } else {
            params[key] = value;
        }
    }
});

if (!params.url_capture || !params.output_file) {
    console.error('Missing required parameters: url_capture and output_file');
    process.exit(1);
}

takeScreenshot(params);