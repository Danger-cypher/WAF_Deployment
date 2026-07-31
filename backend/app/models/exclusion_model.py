from pydantic import BaseModel
from typing import Optional, Union


class ExclusionCreateRequest(BaseModel):
    false_positive_id: Optional[Union[int, str]] = None
    rule_id: str
    exclusion_type: (
        str  # 'uri', 'parameter', 'uri_parameter', 'endpoint_method', 'ip_suppression'
    )
    uri: Optional[str] = None
    parameter_name: Optional[str] = None
    http_method: Optional[str] = None
    client_ip: Optional[str] = None
    notes: str


class ExclusionPreviewRequest(BaseModel):
    rule_id: str
    exclusion_type: str
    uri: Optional[str] = None
    parameter_name: Optional[str] = None
    http_method: Optional[str] = None
    client_ip: Optional[str] = None


class ExclusionStatusUpdateRequest(BaseModel):
    status: str


class ExclusionNoteUpdateRequest(BaseModel):
    notes: str


class ExclusionResponse(BaseModel):
    id: int
    false_positive_id: Optional[Union[int, str]] = None
    rule_id: str
    exclusion_type: str
    uri: Optional[str] = None
    parameter_name: Optional[str] = None
    http_method: Optional[str] = None
    client_ip: Optional[str] = None
    status: str
    created_by: str
    created_at: str
    notes: str
    modsec_rule: str

    class Config:
        from_attributes = True
