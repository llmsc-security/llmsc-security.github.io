#!/usr/bin/env python3
"""
Playwright script to test and compare two deployed websites with detailed JS analysis.
"""

from playwright.sync_api import sync_playwright
import json
import os
import subprocess

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
        return None

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

    # Get JS info with detailed script analysis
    js_info = page.evaluate("""
        () => {
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
                allScriptText: allScriptText,
                scriptCount: scriptElements.length,
                lineMap: scriptLineMap.slice(510, 526), // Lines around 521
                scriptEnd: allScriptText.slice(-500) // Last 500 chars
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

def check_local_file(filepath):
    """Read and check the local file for syntax issues."""
    with open(filepath, 'r') as f:
        content = f.read()

    # Find the script content
    import re
    script_match = re.search(r'<script>(.*?)</script>', content, re.DOTALL)
    if script_match:
        script_content = script_match.group(1)
        lines = script_content.split('\n')
        return {
            "script_lines": lines,
            "total_lines": len(lines),
            "line_521": lines[520] if len(lines) > 520 else None,
            "lines_515_526": lines[515:526] if len(lines) > 526 else None
        }
    return None

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

        if not main_info:
            print("\n\nMain site returned 404 or error - checking local file")
            local_info = check_local_file("/mnt/nvme/wj_code/dl_llmsc/llmsc-security.github.io_update/deploy/index.html")
            if local_info:
                print(f"\nLocal file script info:")
                print(f"  Total script lines: {local_info['total_lines']}")
                print(f"  Line 521: {repr(local_info['line_521'])}")
                print(f"  Lines 515-526:")
                for i, line in enumerate(local_info['lines_515_526'], start=515):
                    print(f"    {i}: {repr(line)}")

        if test_info and test_info.get("js_info"):
            print(f"\n\nTest Site JS Analysis:")
            print(f"  Script count: {test_info['js_info']['scriptCount']}")
            print(f"  Document ready: {test_info['js_info']['documentReady']}")
            print(f"  Lines 515-526:")
            for line_info in test_info['js_info']['lineMap']:
                print(f"    Line {line_info['line']}: {repr(line_info['content'])}")
            print(f"  Script end snippet: {repr(test_info['js_info']['scriptEnd'][:200])}")

        # Save HTML contents to files for comparison
        os.makedirs("/tmp/website_comparison", exist_ok=True)

        if main_info:
            with open("/tmp/website_comparison/main_site.html", "w") as f:
                f.write(main_info["html_content"])

        if test_info:
            with open("/tmp/website_comparison/test_site.html", "w") as f:
                f.write(test_info["html_content"])

        # Save console errors to JSON
        with open("/tmp/website_comparison/errors.json", "w") as f:
            json.dump({
                "main_site": main_info["console_errors"] if main_info else "404 Not Found",
                "test_site": test_info["console_errors"] if test_info else "404 Not Found"
            }, f, indent=2)

        # Print summary
        print("\n\n" + "="*80)
        print("SUMMARY")
        print("="*80)

        if main_info:
            print(f"\nMain Site ({main_url}):")
            print(f"  Console Errors: {len(main_info['console_errors'])}")
            for err in main_info['console_errors']:
                print(f"    - {err['text']}")
        else:
            print(f"\nMain Site ({main_url}): NOT FOUND - Returns 404")

        if test_info:
            print(f"\nTest Site ({test_url}):")
            print(f"  Console Errors: {len(test_info['console_errors'])}")
            for err in test_info['console_errors']:
                print(f"    - {err['text']}")
        else:
            print(f"\nTest Site ({test_url}): NOT FOUND - Returns 404")

        print(f"\nHTML saved to:")
        print(f"  - /tmp/website_comparison/main_site.html")
        print(f"  - /tmp/website_comparison/test_site.html")
        print(f"  - /tmp/website_comparison/errors.json")

if __name__ == "__main__":
    main()
