# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import gettext
import locale
import os


LOCALE_DIR = os.path.join("precli", "locale")


def set_language(lang_code: str = None) -> None:
    global _
    system_locale, _ = locale.getdefaultlocale()
    lang_code = (
        lang_code or system_locale.split("_")[0] if system_locale else "en"
    )

    try:
        lang = gettext.translation(
            "messages",
            localedir=LOCALE_DIR,
            languages=[lang_code],
            fallback=True,
        )
        lang.install()
        _ = lang.gettext
    except FileNotFoundError:

        def translate(text: str) -> str:
            return text

        _ = translate


set_language()
