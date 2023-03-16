import uuid
from dataclasses import dataclass, field
from typing import List, Optional

from ._provenance import SystemProvenance

# pylint: disable=too-many-instance-attributes


@dataclass
class System:
    UUID: str = field(default_factory=uuid.uuid4)
    captureStart: Optional[int] = None
    captureEnd: Optional[int] = None
    name: Optional[str] = None
    officialName: Optional[str] = None
    vendor: Optional[List[str]] = None
    description: Optional[str] = None
    provenance: Optional[List[SystemProvenance]] = None
