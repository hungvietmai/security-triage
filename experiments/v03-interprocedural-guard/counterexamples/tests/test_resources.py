"""Test code (SPEC_RESOURCE assumption S-TEST): rebinding a store root here does not run in a deployment."""

import resources


def test_tested_store(tmp_path):
    resources.TESTED = tmp_path / "tested"
