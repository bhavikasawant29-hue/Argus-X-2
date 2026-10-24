"""Asset Inventory Data Model for ARGUS-X."""

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class InstalledSoftware(BaseModel):
    vendor: str
    product: str
    version: Optional[str] = None
    cpe: Optional[str] = None


class AssetRecord(BaseModel):
    asset_id: str
    hostname: str
    ip_address: Optional[str] = None
    asset_type: str = "workstation"  # workstation, server, database
    criticality: str = "medium"      # low, medium, high, critical
    owner: Optional[str] = None
    installed_software: List[InstalledSoftware] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

