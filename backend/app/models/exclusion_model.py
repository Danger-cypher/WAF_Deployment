from pydantic import BaseModel
from typing import Optional, Union


class ExclusionCreateRequest(BaseModel):
    false_positive_id: Optional[Union[int, str]] = None
    rule_id: str
    exclusion_type: (
        # 'host' matches REQUEST_HEADERS:Host via the `uri` field (no
        # dedicated column — see rule_manager.generate_modsec_rule) rather
        # than REQUEST_URI; used for vhost-wide exclusions like a
        # DNS-less admin dashboard's own numeric-IP Host header.
        str  # 'uri', 'parameter', 'uri_parameter', 'endpoint_method', 'ip_suppression', 'host'
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
