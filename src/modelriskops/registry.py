from __future__ import annotations

from .models import ModelRecord


class ModelRegistry:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], ModelRecord] = {}

    def register(self, record: ModelRecord) -> None:
        key = (record.institution_id, record.model_id)
        if key in self._records:
            raise ValueError("model id already registered for institution")
        self._records[key] = record

    def get(self, institution_id: str, model_id: str) -> ModelRecord | None:
        return self._records.get((institution_id, model_id))

    def list_for_institution(self, institution_id: str) -> tuple[ModelRecord, ...]:
        return tuple(sorted((record for (tenant, _), record in self._records.items() if tenant == institution_id), key=lambda item: item.model_id))
