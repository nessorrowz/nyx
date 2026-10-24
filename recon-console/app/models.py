"""The data model behind the UI.

Each screen in the mockup maps to a table here:
  Projects & Targets -> Project
  Scan Jobs          -> ScanJob
  Assets & Services  -> Asset + Service
  Findings           -> Finding
"""
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import SQLModel, Field


class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanJob(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id")
    target: str
    scan_mode: str                      # single | custom | full
    profile: str                        # discovery | standard | extended
    modules: str = ""                   # comma-separated module names
    status: str = "queued"              # queued | running | completed | failed
    scope_confirmed: bool = False
    log: str = ""
    error: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None


class Asset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_job_id: int = Field(foreign_key="scanjob.id", index=True)
    ip: str = Field(index=True)
    hostname: str = ""
    os_guess: str = ""
    status: str = "up"


class Service(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    asset_id: int = Field(foreign_key="asset.id", index=True)
    port: int
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    state: str = "open"


class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    scan_job_id: int = Field(foreign_key="scanjob.id", index=True)
    asset_ip: str = ""
    severity: str = "info"              # info | low | medium | high | critical
    title: str = ""
    detail: str = ""
    source_tool: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
