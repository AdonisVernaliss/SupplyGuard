from typing import Annotated, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.config import Settings, get_settings
from app.database import get_session
from app.localization import localized_report
from app.models import AnalysisListItem, AnalysisReport, HealthResponse
from app.parser import BomParseError
from app.profile import supported_profile
from app.repository import get_report, list_reports, save_report
from app.service import analyze_bom, demo_bom_bytes
from app.vulnerabilities import (
    DemoVulnerabilityProvider,
    OsvVulnerabilityProvider,
    VulnerabilityProvider,
    VulnerabilityProviderError,
)

router = APIRouter(prefix="/api/v1")


@router.get("/health", response_model=HealthResponse)
def health(settings: Annotated[Settings, Depends(get_settings)]) -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        supported_profile=supported_profile(),
    )


@router.post("/analyses", response_model=AnalysisReport, status_code=status.HTTP_201_CREATED)
async def create_analysis(
    file: Annotated[UploadFile, File(description="CycloneDX JSON SBOM")],
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    provider: Annotated[Literal["osv", "demo"], Query()] = "osv",
) -> AnalysisReport:
    payload = await file.read(settings.max_upload_bytes + 1)
    if len(payload) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="The SBOM exceeds the 5 MiB upload limit.")
    if not payload:
        raise HTTPException(status_code=400, detail="The uploaded SBOM is empty.")

    vulnerability_provider = _provider(provider, settings)
    try:
        report = await analyze_bom(
            payload=payload,
            filename=file.filename or "uploaded.cdx.json",
            provider=vulnerability_provider,
            max_scanned_components=settings.max_scanned_components,
        )
    except BomParseError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except VulnerabilityProviderError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    save_report(session, report)
    return report


@router.post("/analyses/demo", response_model=AnalysisReport, status_code=status.HTTP_201_CREATED)
async def create_demo_analysis(
    session: Annotated[Session, Depends(get_session)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> AnalysisReport:
    report = await analyze_bom(
        payload=demo_bom_bytes(),
        filename="demo-shop.cdx.json",
        provider=DemoVulnerabilityProvider(),
        max_scanned_components=settings.max_scanned_components,
    )
    save_report(session, report)
    return report


@router.get("/analyses", response_model=list[AnalysisListItem])
def analysis_history(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[AnalysisListItem]:
    return list_reports(session, limit)


@router.get("/analyses/{analysis_id}", response_model=AnalysisReport)
def analysis_detail(
    analysis_id: str, session: Annotated[Session, Depends(get_session)]
) -> AnalysisReport:
    report = get_report(session, analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return report


@router.get("/analyses/{analysis_id}/report")
def analysis_report(
    analysis_id: str,
    session: Annotated[Session, Depends(get_session)],
    lang: Annotated[Literal["en", "de", "ru"], Query()] = "en",
) -> JSONResponse:
    report = get_report(session, analysis_id)
    if not report:
        raise HTTPException(status_code=404, detail="Analysis not found.")
    return JSONResponse(
        content=localized_report(report, lang),
        headers={
            "Content-Disposition": (
                f'attachment; filename="supplyguard-{analysis_id[:8]}-{lang}.json"'
            )
        },
    )


def _provider(name: str, settings: Settings) -> VulnerabilityProvider:
    if name == "demo":
        return DemoVulnerabilityProvider()
    return OsvVulnerabilityProvider(
        base_url=settings.osv_base_url,
        timeout_seconds=settings.osv_timeout_seconds,
    )
