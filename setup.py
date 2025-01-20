#!/usr/bin/env python

from setuptools import setup

# Metadata goes in setup.cfg. These are here for GitHub's dependency graph.
setup(
    name="BTFWMergeTool_v3",
    package_data={
        "BTFWMergeTool_v3": ["default_config.toml"]
    }
)
