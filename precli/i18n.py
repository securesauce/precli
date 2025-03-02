# Copyright 2024 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import gettext
import locale

LOCALE_DIR = "locale"


def default(text: str) -> str:
    return text


def set_language() -> None:
    global _
    system_locale, _ = locale.getdefaultlocale()
    lang_code = system_locale.split("_")[0] if system_locale else "en"

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
        _ = default


set_language()
