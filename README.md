# Screenshooter

**Screenshooter** is an enhanced web screenshot tool built on top of the webscreenshot project by [maaaaz](https://github.com/maaaaz). It captures screenshots of web pages using various renderers (e.g., Chromium via Puppeteer) and generates a dark-themed, interactive HTML report with pagination, filtering, sorting, and a "Show All" feature. The tool is designed for security researchers, penetration testers, and developers to efficiently visualize and analyze web page screenshots.

## Features

- **Screenshot Capture**: Supports multiple renderers (PhantomJS, Chrome, Chromium, EdgeChromium, Firefox) with configurable options like window size, timeout, and HTTP headers.
- **Parallel Processing**: Uses multiprocessing to capture screenshots concurrently, with configurable worker threads.
- **Metadata Collection**: Saves detailed metadata (URL, status, headers, title, errors) in `output/results.json`.
- **Automatic Report Generation**: Generates an HTML report (`report.html`) with a dark-themed, interactive UI:
  - **Pagination**: Displays 20 screenshots per page.
  - **Filtering**: Filter by HTTP status (e.g., 200, 404).
  - **Sorting**: Sort by URL, title, or status.
  - **Show All**: Reset to display all screenshots.
- **Headless Support**: Runs without an X server using `xvfb-run` for compatibility with headless environments like Kali Linux.
- **Error Handling**: Logs failed URLs and supports retries for robustness.
- **Customizable**: Supports proxies, cookies, HTTP authentication, and custom JavaScript injection.

## Built On

This tool extends the original webscreenshot project, adding:

- Automatic HTML report generation with `generate_report.py`.
- A modern, dark-themed UI using Tailwind CSS.
- Enhanced logging and user feedback for report generation.

## Installation

### Prerequisites

- **Python**: 3.6 or higher
- **Node.js and npm**: For Puppeteer (Chromium renderer)
- **Browsers**: Chromium or Firefox for rendering
- **xvfb** (optional): For headless environments
- **Imagemagick** (optional): For labeled screenshots

Install dependencies on Kali Linux or similar:

```bash
sudo apt-get install python3 python3-pip nodejs npm chromium-browser firefox-esr xvfb imagemagick
```

Install Puppeteer:

```bash
npm install puppeteer
```

### Clone the Repository

```bash
git clone https://github.com/abderaoufzx/screenshooter.git
cd screenshooter
```

### Verify Files

Ensure the following files are present:

- `webscreenshot.py`: Main script for screenshot capture.
- `generate_report.py`: Script to generate the HTML report.
- `screenshooter_puppeteer.js`: Puppeteer script for Chromium rendering.
- `screenshooter.js` (optional): For PhantomJS rendering.

## Usage

### Basic Command

Capture screenshots from a list of URLs and generate an HTML report:

```bash
python3 webscreenshot.py -i urls.txt -r chromium -vv --no-xserver -w 1 -t 60
```

### Command-Line Options

```bash
usage: webscreenshot.py [-h] [--input-file INPUT_FILE] [--subfinder-input SUBFINDER_INPUT]
                        [-o OUTPUT_DIRECTORY] [-w WORKERS] [-v] [--no-error-file]
                        [-z SINGLE_OUTPUT_FILE] [--retries RETRIES] [-p PORT] [-s]
                        [-m] [-r {phantomjs,chrome,chromium,edgechromium,firefox}]
                        [--renderer-binary RENDERER_BINARY] [--no-xserver]
                        [--window-size WINDOW_SIZE] [-f {pdf,png,jpg,jpeg,bmp,ppm}]
                        [-q [0-100]] [--ajax-max-timeouts AJAX_MAX_TIMEOUTS]
                        [--crop CROP] [--custom-js CUSTOM_JS] [-l] [--label-size LABEL_SIZE]
                        [--label-bg-color LABEL_BACKGROUND_COLOR]
                        [--imagemagick-binary LABEL_BINARY] [-c COOKIE_STRING]
                        [-a HEADER] [-u HTTP_USERNAME] [-b HTTP_PASSWORD] [-P PROXY]
                        [-A PROXY_AUTH] [-T {http,none,socks5}] [-t TIMEOUT]
                        [URL]

Main parameters:
  URL                   Single URL target given as a positional argument
  -i, --input-file      Text file containing the target list (e.g., list.txt)
  --subfinder-input     JSON output file from subfinder
  -o, --output-directory
                        Screenshots output directory (default: ./output/)
  -w, --workers         Number of parallel execution workers (default: 4)
  -v, --verbosity       Verbosity level {-v INFO, -vv DEBUG} (default: ERROR)
  --no-error-file       Do not write a file with failed URLs
  -z, --single-output-file
                        Name of a single output file for all inputs (e.g., test.png)
  --retries             Number of retries for failed screenshots (default: 2)

Input processing parameters:
  -p, --port            Use the specified port for each target (e.g., 80)
  -s, --ssl             Enforce SSL/TLS for every connection
  -m, --multiprotocol   Perform screenshots over HTTP and HTTPS

Screenshot renderer parameters:
  -r, --renderer        Renderer to use (default: chromium)
  --renderer-binary     Path to the renderer executable if not in $PATH
  --no-xserver          Use xvfb-run if no X server

Screenshot image parameters:
  --window-size         Width and height of the screen capture (default: 1200,800)
  -f, --format          Output image format (phantomjs only, default: png)
  -q, --quality         Output image quality, 0-100 (phantomjs only, default: 75)
  --ajax-max-timeouts   AJAX and max URL timeout in ms (phantomjs only, default: 1400,1800)
  --crop                Rectangle <t,l,w,h> to crop (phantomjs only)
  --custom-js           Path to JavaScript file to execute before screenshot

Screenshot label parameters:
  -l, --label           Create a screenshot with the target URL (requires imagemagick)
  --label-size          Font size for the label (default: 60)
  --label-bg-color      Label background color (default: NavajoWhite)
  --imagemagick-binary  Path to imagemagick binary if not in $PATH

HTTP parameters:
  -c, --cookie          Cookie string (e.g., "JSESSIONID=1234; YOLO=SWAG")
  -a, --header          Custom header (e.g., "Host: localhost")
  -u, --http-username   Username for HTTP Basic Authentication
  -b, --http-password   Password for HTTP Basic Authentication

Connection parameters:
  -P, --proxy           Specify a proxy (e.g., http://proxy.company.com:8080)
  -A, --proxy-auth      Proxy authentication (e.g., user:password)
  -T, --proxy-type      Proxy type: http, none, socks5 (default: http)
  -t, --timeout         Renderer timeout in seconds (default: 30)
```

### Example Commands

- **Capture screenshots from a file**:

  ```bash
  python3 webscreenshot.py -i urls.txt -r chromium -vv --no-xserver -w 4 -t 30
  ```

  - Processes URLs in `urls.txt`, saves screenshots to `output/`, generates `results.json`, and creates `report.html`.

- **Single URL**:

  ```bash
  python3 webscreenshot.py https://example.com -r chromium -vv
  ```

- **With proxy and authentication**:

  ```bash
  python3 webscreenshot.py -i urls.txt -r chromium -P http://proxy.com:8080 -A user:pass -u admin -b password
  ```

- **Labeled screenshots**:

  ```bash
  python3 webscreenshot.py -i urls.txt -r chromium -l --label-size 80
  ```

### Output

- **Screenshots**: Saved in `output/` (e.g., `http_example.com.png`).
- **Metadata**: `output/results.json` with URL, screenshot path, status, headers, title, and errors.
- **Report**: `report.html` with a dark-themed, interactive UI.
- **Failed URLs**: `screenshots_failed.txt` (unless `--no-error-file` is used).

### Report Features

The generated `report.html` includes:

- **Dark Theme**: Gradient background (dark gray to black), dark cards with light text.
- **Responsive Grid**: 1-3 columns based on screen size.
- **Pagination**: 20 screenshots per page with numbered buttons.
- **Filtering**: Buttons to filter by HTTP status (e.g., 200, 404).
- **Sorting**: Sort by URL, title, or status.
- **Show All**: Reset to display all screenshots.
- **Styling**: Powered by Tailwind CSS (requires internet for CDN).

### Troubleshooting

- **No report generated**:
  - Ensure `generate_report.py` is in the same directory.
  - Check logs with `-vv`:

    ```bash
    python3 webscreenshot.py -i urls.txt -r chromium -vv
    ```
  - Run `generate_report.py` manually:

    ```bash
    python3 generate_report.py output/results.json -o report.html
    ```
- **Styling issues**:
  - Verify internet connectivity for Tailwind CSS CDN (`https://cdn.tailwindcss.com`).
  - Open `report.html` in Chromium or Firefox and check console errors (F12).
  - Clear browser cache:

    ```bash
    chromium-browser --clear-cache
    ```
- **Puppeteer errors**:
  - Ensure Node.js and Puppeteer are installed.
  - Test `screenshooter_puppeteer.js`:

    ```bash
    node screenshooter_puppeteer.js --version
    ```

### Acknowledgments

- **Original Project**: webscreenshot by [maaaaz](https://github.com/maaaaz).
- **Enhancements**: Added automatic report generation, dark-themed UI, and interactive features by [abderaoufzx](https://github.com/abderaoufzx).

### License

This project inherits the license of the original webscreenshot project (MIT License). See the original repository for details.