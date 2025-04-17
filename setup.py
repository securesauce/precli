# Copyright 2025 Secure Sauce LLC
# SPDX-License-Identifier: BUSL-1.1
import setuptools


setuptools.setup(
    python_requires=">=3.10",
    setup_requires=["pbr>=2.0.0"],
    pbr=True,
    package_data={
        "precli": ["locale/*/LC_MESSAGES/*.mo"],
    },
)
