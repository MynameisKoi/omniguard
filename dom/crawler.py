from playwright.sync_api import sync_playwright


def analyze_page(url):

    with sync_playwright() as p:

        browser = p.chromium.launch(headless=True)

        page = browser.new_page()

        page.goto(url, wait_until="domcontentloaded")

        title = page.title()

        forms = page.locator("form")

        form_count = forms.count()

        credential_form = False
        username_field = False
        password_field = False

        form_actions = []

        for i in range(form_count):

            form = forms.nth(i)

            password_fields = form.locator(
                "input[type='password']"
            )

            username_fields = form.locator(
                "input[type='text'], "
                "input[type='email'], "
                "input[name*='user'], "
                "input[name*='email']"
            )

            if password_fields.count() > 0:
                password_field = True

            if username_fields.count() > 0:
                username_field = True

            if password_fields.count() > 0 and username_fields.count() > 0:
                credential_form = True

            action = form.get_attribute("action")

            if action is None:
                action = url

            form_actions.append(action)

        result = {
            "url": url,
            "title": title,
            "form_count": form_count,
            "credential_form": credential_form,
            "username_field": username_field,
            "password_field": password_field,
            "form_actions": form_actions
        }

        browser.close()

        return result