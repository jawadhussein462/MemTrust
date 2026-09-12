"""Backend integrations.

Each integration lives in its own submodule and imports its provider SDK
lazily, so ``pip install memtrust`` stays lightweight. Install the extra you
need, e.g. ``pip install "memtrust[mem0]"``.

    from memtrust.integrations.mem0 import Mem0Backend
    from memtrust.integrations.langgraph import LangGraphStoreBackend
    from memtrust.integrations.zep import ZepBackend          # experimental
    from memtrust.integrations.generic import FunctionBackend
"""

from __future__ import annotations

__all__: list[str] = []
