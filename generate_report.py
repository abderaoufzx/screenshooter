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

def render_card(entry):
    """Render a single card for a result entry."""
    url = entry.get("url", "Unknown")
    screenshot = entry.get("screenshot", "")
    status = str(entry.get("status", "Unknown"))
    headers = entry.get("headers", {})
    title = entry.get("title", "No title")
    error = entry.get("error", "None")

    screenshot_rel = os.path.join("screenshots", os.path.basename(screenshot)) if screenshot else ""
    screenshot_html = (
        f'<a href="{screenshot_rel}" target="_blank"><img src="{screenshot_rel}" alt="Screenshot" class="w-full rounded-lg"></a>'
        if screenshot and os.path.exists(screenshot)
        else '<div class="text-red-400">Screenshot missing</div>'
    )

    headers_html = "<br>".join(f"<b>{k}:</b> {v}" for k, v in headers.items()) or "No headers"

    return f"""
    <div class="card bg-gray-800 shadow-lg rounded-lg p-4 border border-gray-700">
        {screenshot_html}
        <div class="mt-2 url"><b class="text-gray-300">URL:</b> <a href="{url}" target="_blank" class="text-blue-400 hover:underline">{url}</a></div>
        <div class="title"><b class="text-gray-300">Title:</b> <span class="text-gray-200">{title}</span></div>
        <div class="status"><b class="text-gray-300">Status:</b> <span class="text-gray-200">{status}</span></div>
        <div><b class="text-gray-300">Error:</b> <span class="text-gray-200">{error}</span></div>
        <div class="headers mt-2 p-2 bg-gray-900 rounded text-sm font-mono text-gray-300 overflow-auto max-h-48">{headers_html}</div>
    </div>
    """

def render_paginated_content(results, page_size=20):
    """Render cards grouped into paginated divs."""
    if not results:
        return '<div class="text-center text-gray-400">No results to display</div>'

    pages = []
    for i in range(0, len(results), page_size):
        page_cards = [render_card(entry) for entry in results[i:i + page_size]]
        pages.append(f'<div class="page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">{''.join(page_cards)}</div>')
    return "".join(pages)

def generate_html(results):
    """Generate the complete HTML report."""
    content = render_paginated_content(results)
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
        let originalCards = [];

        function showPage(pageIndex) {{
            console.log('Showing page:', pageIndex);
            const pages = document.querySelectorAll('.page');
            if (!pages.length) {{
                console.log('No pages found');
                document.getElementById('pagination').innerHTML = '<p class="text-gray-400">No results to display</p>';
                return;
            }}
            pages.forEach((page, i) => {{
                page.classList.toggle('active', i === pageIndex);
            }});
            const buttons = document.querySelectorAll('.pagination-btn');
            buttons.forEach((btn, i) => {{
                btn.classList.toggle('bg-blue-700', i === pageIndex);
                btn.classList.toggle('bg-blue-500', i !== pageIndex);
            }});
        }}

        function createPagination() {{
            console.log('Creating pagination...');
            const pages = document.querySelectorAll('.page');
            const pagination = document.getElementById('pagination');
            pagination.innerHTML = '';
            if (!pages.length) {{
                console.log('No pages to paginate');
                pagination.innerHTML = '<p class="text-gray-400">No results to display</p>';
                return;
            }}
            pages.forEach((_, i) => {{
                const btn = document.createElement('button');
                btn.textContent = i + 1;
                btn.className = 'pagination-btn px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 transition';
                btn.addEventListener('click', () => {{
                    console.log('Pagination button clicked:', i);
                    showPage(i);
                }});
                pagination.appendChild(btn);
            }});
            showPage(0);
        }}

        function filterByStatus(status) {{
            console.log('Filtering by status:', status);
            const content = document.getElementById('report-content');
            content.innerHTML = '';
            const filteredCards = originalCards.filter(card => {{
                const statusDiv = card.querySelector('.status');
                return statusDiv && statusDiv.textContent.includes(`Status: ${{status}}`);
            }});
            const pageSize = 20;
            for (let i = 0; i < filteredCards.length; i += pageSize) {{
                const page = document.createElement('div');
                page.className = 'page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6';
                filteredCards.slice(i, i + pageSize).forEach(card => {{
                    page.appendChild(card.cloneNode(true));
                }});
                content.appendChild(page);
            }}
            createPagination();
        }}

        function sortCards(criteria) {{
            console.log('Sorting by:', criteria);
            const content = document.getElementById('report-content');
            const sortedCards = [...originalCards].sort((a, b) => {{
                let aValue, bValue;
                if (criteria === 'url') {{
                    aValue = a.querySelector('.url a')?.textContent || '';
                    bValue = b.querySelector('.url a')?.textContent || '';
                }} else {{
                    aValue = a.querySelector(`.${{criteria}}`)?.textContent.split(': ')[1] || '';
                    bValue = b.querySelector(`.${{criteria}}`)?.textContent.split(': ')[1] || '';
                }}
                return aValue.localeCompare(bValue);
            }});
            content.innerHTML = '';
            const pageSize = 20;
            for (let i = 0; i < sortedCards.length; i += pageSize) {{
                const page = document.createElement('div');
                page.className = 'page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6';
                sortedCards.slice(i, i + pageSize).forEach(card => {{
                    page.appendChild(card.cloneNode(true));
                }});
                content.appendChild(page);
            }}
            createPagination();
        }}

        function showAll() {{
            console.log('Showing all cards');
            const content = document.getElementById('report-content');
            content.innerHTML = '';
            const pageSize = 20;
            for (let i = 0; i < originalCards.length; i += pageSize) {{
                const page = document.createElement('div');
                page.className = 'page hidden grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6';
                originalCards.slice(i, i + pageSize).forEach(card => {{
                    page.appendChild(card.cloneNode(true));
                }});
                content.appendChild(page);
            }}
            createPagination();
        }}

        window.onload = function() {{
            console.log('Initializing report...');
            originalCards = Array.from(document.querySelectorAll('.card'));
            const statuses = [...new Set(originalCards.map(card => {{
                const statusDiv = card.querySelector('.status');
                return statusDiv ? statusDiv.textContent.split(': ')[1] : 'unknown';
            }}))];
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