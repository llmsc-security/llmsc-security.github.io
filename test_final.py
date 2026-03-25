#!/usr/bin/env python3
"""
Final Playwright test to compare websites and detect JS syntax errors.
"""

from playwright.sync_api import sync_playwright
import json
import os

def main():
    test_url = "https://llmsc-security-test.github.io/deploy/index.html"
    main_url = "https://llmsc-security.github.io/deploy/index.html"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Test the main site first
        print("="*80)
        print("MAIN SITE:", main_url)
        print("="*80)
        page_main = browser.new_page()

        # Set up console error capture
        main_errors = []
        page_main.on("console", lambda msg: main_errors.append({
            "type": msg.type,
            "text": msg.text,
            "location": str(msg.location)
        }))

        try:
            page_main.goto(main_url, wait_until="networkidle", timeout=30000)
        except Exception as e:
            print(f"Navigation error: {e}")

        page_main.wait_for_timeout(2000)

        main_html = page_main.content()
        main_script_content = page_main.evaluate("""
            () => {
                const scriptEl = document.querySelector('script');
                if (scriptEl) {
                    return scriptEl.innerHTML.substring(0, 10000);
                }
                return '';
            }
        """)

        main_js_errors = page_main.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script');
                let result = [];
                scripts.forEach((s, i) => {
                    if (s.innerHTML) {
                        result.push({
                            index: i,
                            length: s.innerHTML.length,
                            first500: s.innerHTML.substring(0, 500),
                            last500: s.innerHTML.substring(Math.max(0, s.innerHTML.length - 500))
                        });
                    }
                });
                return result;
            }
        """)

        print(f"\nConsole Errors ({len(main_errors)}):")
        for err in main_errors:
            print(f"  [{err['type']}] {err['text']}")
            print(f"    Location: {err['location']}")

        print(f"\nScript elements: {len(main_js_errors)}")
        for s in main_js_errors:
            print(f"  Script #{s['index']}: {s['length']} chars")
            # Try to parse JS for syntax errors
            try:
                page_main.evaluate("""
                    () => {
                        const jsText = `%s";
                        // Try to compile as function
                        try {
                            new Function(jsText);
                            return 'OK';
                        } catch(e) {
                            return e.message;
                        }
                    }
                """ % s['first500'][:500])
            except Exception as e:
                print(f"    JS Parse Error: {e}")

        # Save main site HTML
        os.makedirs("/tmp/website_comparison", exist_ok=True)
        with open("/tmp/website_comparison/main_site.html", "w") as f:
            f.write(main_html)

        print("\n" + "="*80)
        print("TEST SITE:", test_url)
        print("="*80)
        page_test = browser.new_page()

        test_errors = []
        page_test.on("console", lambda msg: test_errors.append({
            "type": msg.type,
            "text": msg.text,
            "location": str(msg.location)
        }))

        try:
            page_test.goto(test_url, wait_until="networkidle", timeout=30000)
        except Exception as e:
            print(f"Navigation error: {e}")

        page_test.wait_for_timeout(2000)

        test_html = page_test.content()
        test_js_errors = page_test.evaluate("""
            () => {
                const scripts = document.querySelectorAll('script');
                let result = [];
                scripts.forEach((s, i) => {
                    if (s.innerHTML) {
                        result.push({
                            index: i,
                            length: s.innerHTML.length,
                            first500: s.innerHTML.substring(0, 500),
                            last500: s.innerHTML.substring(Math.max(0, s.innerHTML.length - 500))
                        });
                    }
                });
                return result;
            }
        """)

        print(f"\nConsole Errors ({len(test_errors)}):")
        for err in test_errors:
            print(f"  [{err['type']}] {err['text']}")
            print(f"    Location: {err['location']}")

        print(f"\nScript elements: {len(test_js_errors)}")
        for s in test_js_errors:
            print(f"  Script #{s['index']}: {s['length']} chars")
            # Check around line 521 for syntax error
            try:
                # Extract and analyze lines around 521
                js_lines = s['first500'].split('\n')
                if len(js_lines) >= 20:
                    print(f"    Lines 515-525:")
                    for i in range(15, min(25, len(js_lines))):
                        print(f"      Line {i+1}: {js_lines[i][:80]}")
            except Exception as e:
                print(f"    Analysis Error: {e}")

        # Save test site HTML
        with open("/tmp/website_comparison/test_site.html", "w") as f:
            f.write(test_html)

        # Save errors
        with open("/tmp/website_comparison/errors.json", "w") as f:
            json.dump({
                "main_site_errors": main_errors,
                "test_site_errors": test_errors,
                "main_site_scripts": main_js_errors,
                "test_site_scripts": test_js_errors
            }, f, indent=2)

        # Summary
        print("\n\n" + "="*80)
        print("FINAL SUMMARY")
        print("="*80)

        print(f"\n[MAIN SITE] {main_url}")
        print(f"  - Returns 404: {len(main_html) < 500}")
        print(f"  - Console Errors: {len(main_errors)}")
        if main_errors:
            for err in main_errors:
                if err['type'] == 'error':
                    print(f"    ERROR: {err['text']}")

        print(f"\n[TEST SITE] {test_url}")
        print(f"  - Has correct content: {len(test_html) > 5000}")
        print(f"  - Console Errors: {len(test_errors)}")
        if test_errors:
            for err in test_errors:
                if err['type'] == 'error':
                    print(f"    ERROR: {err['text']}")

        print(f"\nHTML saved to /tmp/website_comparison/")

        browser.close()

if __name__ == "__main__":
    main()
