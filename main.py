from dom.crawler import analyze_page


def main():

    url = input("Enter website URL: ")

    try:

        result = analyze_page(url)

        print("\n===== VerifyEye Result =====")

        print("URL:", result["url"])
        print("Title:", result["title"])
        print("Forms:", result["form_count"])
        print("Credential Form:", result["credential_form"])
        print("Username Field:", result["username_field"])
        print("Password Field:", result["password_field"])

        print("\nForm Actions:")

        for action in result["form_actions"]:
            print("-", action)

    except Exception as error:

        print("Error:", error)


main()