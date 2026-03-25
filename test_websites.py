#!/usr/bin/env python3
"""
Playwright script to test and compare two deployed websites.
"""

from playwright.sync_api import sync_playwright
import json
import os

def capture_page_info(page, site_name, url):
    """Capture console errors, HTML content, and JS info from a page."""
    print(f"\n{'='*80}")
    print(f"Capturing info from: {site_name}")
    print(f"URL: {url}")
    print(f"{'='*80}")

    # Collect console messages
    console_messages = []
    page.on("console", lambda msg: console_messages.append({
        "type": msg.type,
        "text": msg.text,
        "location": str(msg.location)
    }))

    # Navigate and wait for page load
    try:
        page.goto(url, wait_until="networkidle", timeout=30000)
    except Exception as e:
        print(f"Navigation error: {e}")

    # Wait a bit more for any async JS
    page.wait_for_timeout(2000)

    # Get console messages
    errors = [m for m in console_messages if m["type"] == "error"]
    warnings = [m for m in console_messages if m["type"] == "warning"]

    print(f"\n[CONSOLE ERRORS] ({len(errors)} found):")
    for err in errors:
        print(f"  - {err['text']}")
        print(f"    Location: {err['location']}")

    print(f"\n[CONSOLE WARNINGS] ({len(warnings)} found):")
    for warn in warnings:
        print(f"  - {warn['text']}")
        print(f"    Location: {warn['location']}")

    # Get full HTML
    html_content = page.content()

    # Get window.js_errors if any
    js_errors = page.evaluate("window.js_errors || []")

    # Evaluate JavaScript to get more details
    js_info = page.evaluate("""
        () => {
            const errors = [];
            const warnings = [];
            const info = [];

            // Capture console logs
            const originalConsole = { ...console };
            ['error', 'warn', 'info', 'log'].forEach(level => {
                console[level] = function(...args) {
                    errors.push({
                        level: level,
                        message: args.map(a => String(a)).join(' '),
                        stack: new Error().stack
                    });
                    originalConsole[level].apply(originalConsole, args);
                };
            });

            // Get all script tags and their contents
            const scripts = [];
            document.querySelectorAll('script[src], script:not([src])').forEach((script, idx) => {
                scripts.push({
                    index: idx,
                    src: script.src || null,
                    hasContent: !!script.innerHTML,
                    contentPreview: script.innerHTML ? script.innerHTML.substring(0, 200) : null
                });
            });

            // Try to find line 521 and check for syntax issues
            const scriptElements = document.querySelectorAll('script');
            let allScriptText = '';
            let scriptLineMap = [];
            let currentLine = 1;

            scriptElements.forEach((script, idx) => {
                if (script.innerHTML) {
                    const lines = script.innerHTML.split('\\n');
                    lines.forEach((line, lineIdx) => {
                        scriptLineMap.push({
                            scriptIndex: idx,
                            line: currentLine + lineIdx,
                            content: line
                        });
                    });
                    currentLine += lines.length;
                    allScriptText += script.innerHTML + '\\n';
                }
            });

            return {
                location: window.location.href,
                documentReady: document.readyState,
                bodyHTML: document.body.innerHTML.substring(0, 500),
                scripts: scripts,
                allScriptText: allScriptText,
                lineMap: scriptLineMap.slice(515, 526) // Lines around 521
            };
        }
    """)

    return {
        "url": page.url,
        "console_errors": errors,
        "console_warnings": warnings,
        "html_content": html_content,
        "js_info": js_info
    }

def main():
    test_url = "https://llmsc-security-test.github.io/deploy/index.html"
    main_url = "https://llmsc-security.github.io/deploy/index.html"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Test the main site first
        print("Testing main site...")
        page_main = browser.new_page()
        main_info = capture_page_info(page_main, "Main Site", main_url)

        # Test the test site
        print("\n\nTesting test site...")
        page_test = browser.new_page()
        test_info = capture_page_info(page_test, "Test Site", test_url)

        browser.close()

        # Save HTML contents to files for comparison
        os.makedirs("/tmp/website_comparison", exist_ok=True)

        with open("/tmp/website_comparison/main_site.html", "w") as f:
            f.write(main_info["html_content"])

        with open("/tmp/website_comparison/test_site.html", "w") as f:
            f.write(test_info["html_content"])

        # Save console errors to JSON
        with open("/tmp/website_comparison/errors.json", "w") as f:
            json.dump({
                "main_site": {
                    "errors": [e["text"] for e in main_info["console_errors"]],
                    "warnings": [w["text"] for w in main_info["console_warnings"]]
                },
                "test_site": {
                    "errors": [e["text"] for e in test_info["console_errors"]],
                    "warnings": [w["text"] for w in test_info["console_warnings"]]
                }
            }, f, indent=2)

        # Print summary
        print("\n\n" + "="*80)
        print("SUMMARY")
        print("="*80)

        print(f"\nMain Site ({main_url}):")
        print(f"  Console Errors: {len(main_info['console_errors'])}")
        for err in main_info['console_errors']:
            print(f"    - {err['text']}")

        print(f"\nTest Site ({test_url}):")
        print(f"  Console Errors: {len(test_info['console_errors'])}")
        for err in test_info['console_errors']:
            print(f"    - {err['text']}")

        print(f"\nHTML saved to:")
        print(f"  - /tmp/website_comparison/main_site.html")
        print(f"  - /tmp/website_comparison/test_site.html")
        print(f"  - /tmp/website_comparison/errors.json")

if __name__ == "__main__":
    main()
