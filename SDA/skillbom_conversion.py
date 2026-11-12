from copy import deepcopy
from pathlib import Path
import sys
from typing import Any, Dict, List, Mapping, Optional, Union

THIS_DIR = Path(__file__).resolve().parent
REPO_ROOT = THIS_DIR.parent
SIT_ROOT = REPO_ROOT / "SIT"
if str(SIT_ROOT) not in sys.path:
    sys.path.insert(0, str(SIT_ROOT))

from SIT.output.middleware import Middleware
try:
    from .schema import (
        Annotation as SkillBOMAnnotation,
        Component as SkillBOMComponent,
        Relationship as SkillBOMRelationship,
        RuntimeSurface,
        Service as SkillBOMService,
        SkillBOM,
    )
except ImportError:  # pragma: no cover - supports direct script execution
    from schema import (  # type: ignore
        Annotation as SkillBOMAnnotation,
        Component as SkillBOMComponent,
        Relationship as SkillBOMRelationship,
        RuntimeSurface,
        Service as SkillBOMService,
        SkillBOM,
    )


JsonDict = Dict[str, Any]


class Middleware2SkillBOM:
    def __init__(self, midware: Union[Middleware, Mapping[str, Any]]) -> None:
        self.raw_midware = self._dump_model(midware)
        self.midware = midware if isinstance(midware, Middleware) else Middleware(**midware)

    def middleware2skillbom(self) -> dict:
        payload = self._dump_model(self.midware)
        payload["type"] = "SkillBOM"

        if self.midware.components:
            payload["components"] = [
                self.component_mid2skillbom(component) for component in self.midware.components
            ]

        if self.midware.relationship:
            payload["relationship"] = [
                self.relationship_mid2skillbom(relationship)
                for relationship in self.midware.relationship
            ]

        if self.midware.annotations:
            payload["annotations"] = [
                self.annotation_mid2skillbom(annotation)
                for annotation in self.midware.annotations
            ]

        raw_services = self.raw_midware.get("services")
        if raw_services:
            payload["services"] = [
                self.service_mid2skillbom(service) for service in raw_services
            ]

        skillbom = SkillBOM(**payload)
        return skillbom.model_dump(mode="json", by_alias=True, exclude_none=True)

    def component_mid2skillbom(self, component: Union[Any, Mapping[str, Any]]) -> JsonDict:
        data = self._dump_model(component)
        runtime = data.get("runtime") or self.runtime_from_properties(data.get("properties"))
        if runtime:
            data["runtime"] = RuntimeSurface(**runtime).model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
        return SkillBOMComponent(**data).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )

    def service_mid2skillbom(self, service: Union[Any, Mapping[str, Any]]) -> JsonDict:
        data = self._dump_model(service)
        self._normalize_trust_boundary_alias(data)
        if not data.get("type"):
            data["type"] = self.service_type_from_properties(data.get("properties")) or "service"
        return SkillBOMService(**data).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )

    def relationship_mid2skillbom(
        self,
        relationship: Union[Any, Mapping[str, Any]],
    ) -> JsonDict:
        data = self._dump_model(relationship)
        self._apply_relationship_comment_directives(data)
        optional = bool(data.pop("optional", False))
        if data.get("scope") == "unknown":
            data.pop("scope", None)
        inferred_scope = self.relationship_scope(data.get("type"))
        if inferred_scope and not data.get("scope"):
            data["scope"] = inferred_scope
        if optional:
            data["scope"] = "optional"
        return SkillBOMRelationship(**data).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )

    def annotation_mid2skillbom(self, annotation: Union[Any, Mapping[str, Any]]) -> JsonDict:
        data = self._dump_model(annotation)
        if not data.get("subjects"):
            data["subjects"] = []
        if not data.get("annotator"):
            data["annotator"] = []
        return SkillBOMAnnotation(**data).model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )

    def runtime_from_properties(self, properties: Optional[List[JsonDict]]) -> Optional[JsonDict]:
        if not properties:
            return None

        runtime = {}
        for prop in properties:
            key = str(prop.get("key", "")).lower().replace("-", "_")
            value = prop.get("value")
            if value is None:
                continue
            field = self.runtime_property_field(key)
            if field:
                runtime[field] = value

        return runtime if runtime else None

    @staticmethod
    def runtime_property_field(key: str) -> Optional[str]:
        aliases = {
            "runtime_model": "runtime_model",
            "runtime.model": "runtime_model",
            "skillbom.runtime_model": "runtime_model",
            "skillbom.runtime.model": "runtime_model",
            "model_provider": "model_provider",
            "runtime_provider": "model_provider",
            "runtime.provider": "model_provider",
            "skillbom.model_provider": "model_provider",
            "model_version": "model_version",
            "runtime_version": "model_version",
            "runtime.version": "model_version",
            "skillbom.model_version": "model_version",
            "runtime_environment": "runtime_environment",
            "runtime.environment": "runtime_environment",
            "skillbom.runtime_environment": "runtime_environment",
            "runtime_notes": "runtime_notes",
            "runtime.notes": "runtime_notes",
            "skillbom.runtime_notes": "runtime_notes",
        }
        return aliases.get(key)

    @staticmethod
    def service_type_from_properties(properties: Optional[List[JsonDict]]) -> Optional[str]:
        if not properties:
            return None

        for prop in properties:
            key = str(prop.get("key", "")).lower().replace("-", "_")
            value = prop.get("value")
            if key in {"type", "service_type", "skillbom.service_type"} and value:
                return str(value)
        return None

    @staticmethod
    def relationship_scope(relationship_type: Optional[str]) -> Optional[str]:
        if not relationship_type:
            return None

        normalized = relationship_type.upper().replace("-", "_")
        if normalized == "OPTIONAL_DEPENDENCY":
            return "optional"
        if "BUILD" in normalized:
            return "build-time"
        if "RUNTIME" in normalized or normalized in {
            "USES_MCP",
            "USES_SERVICE",
            "USES_DATA",
        }:
            return "runtime"
        if "TEST" in normalized:
            return "test-only"
        return None

    @staticmethod
    def _normalize_trust_boundary_alias(data: JsonDict) -> None:
        if "x_trust_boundary" in data and "x-trust-boundary" not in data:
            data["x-trust-boundary"] = data.pop("x_trust_boundary")

    @staticmethod
    def _apply_relationship_comment_directives(data: JsonDict) -> None:
        comment = str(data.get("comment") or "")
        if "skillbom:optional=true" not in comment:
            return
        data["scope"] = "optional"
        cleaned = comment.replace("; skillbom:optional=true", "")
        cleaned = cleaned.replace("skillbom:optional=true", "")
        cleaned = " | ".join(piece.strip() for piece in cleaned.split("|") if piece.strip())
        if cleaned:
            data["comment"] = cleaned
        else:
            data.pop("comment", None)

    @staticmethod
    def _dump_model(value: Union[Any, Mapping[str, Any]]) -> JsonDict:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json", by_alias=True, exclude_none=True)
        return deepcopy(dict(value))


if __name__ == "__main__":
    import json

    sample_path = Path(__file__).resolve().parent / "output" / "01.json"
    middleware_data = json.loads(sample_path.read_text(encoding="utf-8"))
    skillbom_data = Middleware2SkillBOM(middleware_data).middleware2skillbom()

    print(f"Input: {sample_path}")
    print(f"Document: {skillbom_data['doc_name']}")
    print(f"Type: {middleware_data.get('type')} -> {skillbom_data['type']}")
    print(f"Components: {len(skillbom_data.get('components', []))}")
    print(json.dumps(skillbom_data, ensure_ascii=False, indent=2))
