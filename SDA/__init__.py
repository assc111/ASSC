__version__ = "0.1.0"

import sys
from pathlib import Path

_SIT_ROOT = Path(__file__).resolve().parent.parent / "SIT"
if str(_SIT_ROOT) not in sys.path:
    sys.path.insert(0, str(_SIT_ROOT))

from .enrichment import EnrichmentOptions, EnrichmentReport, enrich_directory, enrich_skillbom
from .generator import (
    generate_and_write_skillbom,
    generate_skillbom,
    generate_skillbom_from_record,
    generate_skillbom_from_text,
    generate_skillbom_model,
    write_skillbom,
)
from .schema import SkillBOM

__all__ = [
    "SkillBOM",
    "__version__",
    "EnrichmentOptions",
    "EnrichmentReport",
    "enrich_directory",
    "enrich_skillbom",
    "generate_and_write_skillbom",
    "generate_skillbom",
    "generate_skillbom_from_record",
    "generate_skillbom_from_text",
    "generate_skillbom_model",
    "write_skillbom",
]
