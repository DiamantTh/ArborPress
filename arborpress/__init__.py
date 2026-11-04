"""ArborPress – minimal, modular identity & auth platform.

ArborPress has no product version number. Deployments identify a build by its
immutable source commit when build metadata is available.
"""

from arborpress._build_info import BUILD_SHA

__all__ = ["BUILD_SHA"]
