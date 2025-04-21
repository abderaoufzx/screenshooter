import json
import os
import sys
from datetime import datetime
import argparse

def load_results(json_file):
    """Load and validate results.json."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("results.json must contain a list of entries")
        return data
    except FileNotFoundError:
        print(f"[ERROR] File {json_file} not found")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {json_file}: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"[ERROR] {e}")
        sys.exit(1)

def render_card(entry, include_image=True):
    """Render a single card for a result entry."""
    url = entry.get("url", "Unknown")
    screenshot = entry.get("screenshot", "")
    status = str(entry.get("status", "Unknown"))
    headers = entry.get("headers", {})
    title = entry.get("title", "No title")
    error = entry.get("error", "None")

    screenshot_rel = os.path.join("output", os.path.basename(screenshot)) if screenshot else ""
    screenshot_html = (
        f'<a href="{screenshot_rel}" target="_blank"><img src="{screenshot_rel}" alt="Screenshot" class="w-full rounded-lg" loading="lazy"></a>'
        if include_image and screenshot and os.path.exists(screenshot)
        else '<div class="text-red-400">Screenshot missing</div>'
    )

    headers_html = "<br>".join(f"<b>{k}:</b> {v}" for k, v in headers.items()) or "No headers"

    return f"""
    <div class="card bg-gray-800 shadow-lg rounded-lg p-4 border border-gray-700" data-url="{url}" data-title="{title}" data-status="{status}">
        {screenshot_html}
        <div class="mt-2 url"><b class="text-gray-300">URL:</b> <a href="{url}" target="_blank" class="text-blue-400 hover:underline">{url}</a></div>
        <div class="title"><b class="text-gray-300">Title:</b> <span class="text-gray-200">{title}</span></div>
        <div class="status"><b class="text-gray-300">Status:</b> <span class="text-gray-200">{status}</span></div>
        <div><b class="text-gray-300">Error:</b> <span class="text-gray-200">{error}</span></div>
        <div class="headers mt-2 p-2 bg-gray-900 rounded text-sm font-mono text-gray-300 overflow-auto max-h-48">{headers_html}</div>
    </div>
    """

def render_paginated_content(results, page_size=20):
    """Render placeholders for paginated divs."""
    if not results:
        return '<div class="text-center text-gray-400">No results to display</div>'

    pages = []
    for i in range(0, len(results), page_size):
        pages.append(f'<div class="page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6" data-page="{i // page_size}"></div>')
    return "".join(pages)

def generate_html(results):
    """Generate the complete HTML report with lazy-loaded images and limited pagination buttons."""
    content = render_paginated_content(results)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    results_json = json.dumps([
        {
            "url": entry.get("url", "Unknown"),
            "screenshot": os.path.join("output", os.path.basename(entry.get("screenshot", ""))) if entry.get("screenshot") else "",
            "status": str(entry.get("status", "Unknown")),
            "title": entry.get("title", "No title"),
            "error": entry.get("error", "None"),
            "headers": entry.get("headers", {})
        } for entry in results
    ])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Screenshooter Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {{
            background: linear-gradient(to bottom, #1f2937, #111827);
            color: #e5e7eb;
            font-family: Arial, sans-serif;
        }}
        .page {{ display: none; }}
        .page.active {{ display: grid; }}
        .headers {{ max-height: 12rem; overflow-y: auto; }}
        .pagination-btn {{ transition: background-color 0.2s; }}
    </style>
</head>
<body class="p-6 min-h-screen">
    <h1 class="text-4xl font-bold text-center mb-6 text-white">Screenshooter Report</h1>
    <p class="text-center text-gray-400 mb-8">Generated: {generated}</p>
    <div class="flex justify-center space-x-4 mb-8">
        <button onclick="sortCards('url')" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 transition">Sort by URL</button>
        <button onclick="sortCards('title')" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 transition">Sort by Title</button>
        <button onclick="sortCards('status')" class="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-500 transition">Sort by Status</button>
    </div>
    <div class="flex justify-center space-x-4 mb-8">
        <button onclick="showAll()" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-500 transition">Show All</button>
        <div id="status-filters" class="flex space-x-4"></div>
    </div>
    <div id="report-content" class="container mx-auto">
        {content}
    </div>
    <div id="pagination" class="flex justify-center space-x-2 mt-8"></div>

    <script>
        const resultsData = {results_json};
        let currentResults = [...resultsData];
        const pageSize = 20;
        const maxButtons = 10;
        let currentButtonStart = 0;
        let currentPage = 0;

        function renderCard(entry, includeImage = true) {{
            const screenshot = includeImage && entry.screenshot ? 
                `<a href="${{entry.screenshot}}" target="_blank"><img src="${{entry.screenshot}}" alt="Screenshot" class="w-full rounded-lg" loading="lazy"></a>` : 
                '<div class="text-red-400">Screenshot missing</div>';
            const headersHtml = Object.entries(entry.headers).map(([k, v]) => `<b>${{k}}:</b> ${{v}}`).join('<br>') || 'No headers';
            return `
                <div class="card bg-gray-800 shadow-lg rounded-lg p-4 border border-gray-700" data-url="${{entry.url}}" data-title="${{entry.title}}" data-status="${{entry.status}}">
                    ${{screenshot}}
                    <div class="mt-2 url"><b class="text-gray-300">URL:</b> <a href="${{entry.url}}" target="_blank" class="text-blue-400 hover:underline">${{entry.url}}</a></div>
                    <div class="title"><b class="text-gray-300">Title:</b> <span class="text-gray-200">${{entry.title}}</span></div>
                    <div class="status"><b class="text-gray-300">Status:</b> <span class="text-gray-200">${{entry.status}}</span></div>
                    <div><b class="text-gray-300">Error:</b> <span class="text-gray-200">${{entry.error}}</span></div>
                    <div class="headers mt-2 p-2 bg-gray-900 rounded text-sm font-mono text-gray-300 overflow-auto max-h-48">${{headersHtml}}</div>
                </div>
            `;
        }}

        function populatePage(pageIndex) {{
            const pageDiv = document.querySelector(`.page[data-page="${{pageIndex}}"]`);
            if (!pageDiv) return;
            pageDiv.innerHTML = '';
            const start = pageIndex * pageSize;
            const end = Math.min(start + pageSize, currentResults.length);
            for (let i = start; i < end; i++) {{
                pageDiv.innerHTML += renderCard(currentResults[i], true);
            }}
        }}

        function showPage(pageIndex) {{
            // console.log('Showing page:', pageIndex);
            const pages = document.querySelectorAll('.page');
            if (!pages.length || pageIndex < 0 || pageIndex >= Math.ceil(currentResults.length / pageSize)) {{
                // console.log('No pages found or invalid page index');
                document.getElementById('pagination').innerHTML = '<p class="text-gray-400">No results to display</p>';
                return;
            }}
            populatePage(pageIndex);
            pages.forEach((page, i) => {{
                page.classList.toggle('active', i === pageIndex);
            }});
            const buttons = document.querySelectorAll('.pagination-btn');
            buttons.forEach((btn) => {{
                const btnIndex = parseInt(btn.dataset.page);
                btn.classList.toggle('bg-blue-700', btnIndex === pageIndex);
                btn.classList.toggle('bg-blue-500', btnIndex !== pageIndex);
            }});
            currentPage = pageIndex;
        }}

        function createPagination() {{
            // console.log('Creating pagination...');
            const pageCount = Math.ceil(currentResults.length / pageSize);
            const pagination = document.getElementById('pagination');
            pagination.innerHTML = '';
            if (pageCount === 0) {{
                // console.log('No pages to paginate');
                pagination.innerHTML = '<p class="text-gray-400">No results to display</p>';
                return;
            }}

            // Calculate button range
            let startButton = currentButtonStart;
            let endButton = Math.min(startButton + maxButtons, pageCount);
            const showEllipsis = endButton < pageCount;
            const showNext = endButton < pageCount;

            // Adjust startButton if currentPage is outside the range
            if (currentPage < startButton) {{
                startButton = Math.max(0, currentPage - maxButtons + 1);
                endButton = Math.min(startButton + maxButtons, pageCount);
            }} else if (currentPage >= endButton) {{
                startButton = Math.max(0, currentPage - maxButtons + 1);
                endButton = Math.min(startButton + maxButtons, pageCount);
            }}
            currentButtonStart = startButton;

            // Show page buttons
            for (let i = startButton; i < endButton; i++) {{
                const btn = document.createElement('button');
                btn.textContent = i + 1;
                btn.dataset.page = i;
                btn.className = 'pagination-btn px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition';
                btn.addEventListener('click', () => {{
                    // console.log('Pagination button clicked:', i);
                    showPage(i);
                }});
                pagination.appendChild(btn);
            }}

            // Add ellipsis
            if (showEllipsis) {{
                const ellipsis = document.createElement('span');
                ellipsis.textContent = '...';
                ellipsis.className = 'px-4 py-2 text-gray-400';
                pagination.appendChild(ellipsis);
            }}

            // Add Next button
            if (showNext) {{
                const nextBtn = document.createElement('button');
                nextBtn.textContent = 'Next';
                nextBtn.className = 'px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition';
                nextBtn.addEventListener('click', () => {{
                    // console.log('Next button clicked');
                    const nextPage = currentPage + 1;
                    if (nextPage < pageCount) {{
                        if (nextPage >= endButton) {{
                            currentButtonStart = Math.min(currentButtonStart + 1, pageCount - maxButtons);
                        }}
                        showPage(nextPage);
                        createPagination();
                    }}
                }});
                pagination.appendChild(nextBtn);
            }}

            // Ensure the current page is shown
            showPage(currentPage);
        }}

        function filterByStatus(status) {{
            // console.log('Filtering by status:', status);
            currentResults = resultsData.filter(entry => entry.status === status);
            currentButtonStart = 0;
            currentPage = 0;
            const content = document.getElementById('report-content');
            content.innerHTML = '';
            const pageCount = Math.ceil(currentResults.length / pageSize);
            for (let i = 0; i < pageCount; i++) {{
                content.innerHTML += `<div class="page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6" data-page="${{i}}"></div>`;
            }}
            createPagination();
        }}

        function sortCards(criteria) {{
            // console.log('Sorting by:', criteria);
            currentResults.sort((a, b) => {{
                const aValue = a[criteria] || '';
                const bValue = b[criteria] || '';
                return aValue.localeCompare(bValue);
            }});
            currentButtonStart = 0;
            currentPage = 0;
            const content = document.getElementById('report-content');
            content.innerHTML = '';
            const pageCount = Math.ceil(currentResults.length / pageSize);
            for (let i = 0; i < pageCount; i++) {{
                content.innerHTML += `<div class="page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6" data-page="${{i}}"></div>`;
            }}
            createPagination();
        }}

        function showAll() {{
            // console.log('Showing all cards');
            currentResults = [...resultsData];
            currentButtonStart = 0;
            currentPage = 0;
            const content = document.getElementById('report-content');
            content.innerHTML = '';
            const pageCount = Math.ceil(currentResults.length / pageSize);
            for (let i = 0; i < pageCount; i++) {{
                content.innerHTML += `<div class="page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6" data-page="${{i}}"></div>`;
            }}
            createPagination();
        }}

        window.onload = function() {{
            // console.log('Initializing report...');
            const statuses = [...new Set(resultsData.map(entry => entry.status))];
            const statusFilters = document.getElementById('status-filters');
            statuses.forEach(status => {{
                const btn = document.createElement('button');
                btn.textContent = `Status: ${{status}}`;
                btn.className = 'px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-500 transition';
                btn.addEventListener('click', () => filterByStatus(status));
                statusFilters.appendChild(btn);
            }});
            createPagination();
        }};
    </script>
</body>
</html>"""

def main():
    parser = argparse.ArgumentParser(description="Generate an HTML report from results.json")
    parser.add_argument("results_file", help="Path to results.json")
    parser.add_argument("-o", "--output", help="Output HTML file", default="report.html")
    args = parser.parse_args()

    results = load_results(args.results_file)
    html = generate_html(results)

    with open(args.output, "w") as f:
        f.write(html)

    print(f"[+] Report written to {args.output}")

if __name__ == "__main__":
    main()