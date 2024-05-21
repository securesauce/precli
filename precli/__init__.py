# Copyright 2024 Secure Sauce LLC
from datetime import datetime
from importlib import metadata


__author__ = metadata.metadata("precli")["Author"]
__summary__ = metadata.metadata("precli")["Summary"]
__copyright__ = f"Copyright {datetime.now():%Y} Secure Sauce LLC"
__download_url__ = metadata.metadata("precli")["Download-URL"]
__url__ = metadata.metadata("precli")["Home-page"]
__version__ = metadata.version("precli")
