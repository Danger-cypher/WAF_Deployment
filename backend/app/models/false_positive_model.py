from pydantic import BaseModel
from typing import Optional, Any, Dict


class FalsePositiveCreateRequest(BaseModel):
    log_id: str
    analyst_note: Optional[str] = ""


class FalsePositiveStatusUpdateRequest(BaseModel):
    status: str


class FalsePositiveNoteUpdateRequest(BaseModel):
    analyst_note: str


class FalsePositiveResponse(BaseModel):
    id: str
    log_id: str
    rule_id: str
    client_ip: str
    uri: str
    timestamp: str
    severity: str
    attack_type: str
    status: str
    analyst_note: str
    raw_log: Dict[str, Any]
    created_by: str = "system"
    # Best-effort suggestion for the Exceptions modal's exclusion_type/parameter_name
    # fields, derived by parsing the matched-variable string CRS already puts in
    # raw_log — never auto-applied, purely a prefill the analyst can override.
    suggested_exclusion: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
