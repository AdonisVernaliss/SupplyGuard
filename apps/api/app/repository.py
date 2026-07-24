from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database import AnalysisRecord
from app.models import AnalysisListItem, AnalysisReport


def save_report(session: Session, report: AnalysisReport) -> None:
    record = AnalysisRecord(
        id=report.id,
        created_at=report.created_at,
        filename=report.document.filename,
        provider=report.provider,
        report=report.model_dump(mode="json", by_alias=True),
    )
    session.add(record)
    session.commit()


def get_report(session: Session, analysis_id: str) -> AnalysisReport | None:
    record = session.get(AnalysisRecord, analysis_id)
    if not record:
        return None
    return AnalysisReport.model_validate(record.report)


def list_reports(session: Session, limit: int = 20) -> list[AnalysisListItem]:
    records = session.scalars(
        select(AnalysisRecord).order_by(desc(AnalysisRecord.created_at)).limit(limit)
    ).all()
    result: list[AnalysisListItem] = []
    for record in records:
        report = AnalysisReport.model_validate(record.report)
        result.append(
            AnalysisListItem(
                id=report.id,
                created_at=report.created_at,
                filename=report.document.filename,
                provider=report.provider,
                component_count=report.summary.component_count,
                vulnerability_count=report.summary.vulnerability_count,
                compliance_score=report.summary.compliance_score,
                risk_score=report.summary.risk_score,
            )
        )
    return result
