"""Administration helper in another module: it rebinds resources.STORE2 through an attribute."""

import resources


def relocate(path):
    resources.STORE2 = path
