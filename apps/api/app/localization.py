from typing import Any

from app.models import AnalysisReport, ValidationFinding

SUPPORTED_LANGUAGES = {"en", "de", "ru"}

MESSAGES: dict[str, dict[str, str]] = {
    "finding.bomFormat": {
        "en": "The document must declare bomFormat as CycloneDX.",
        "de": "Das Dokument muss CycloneDX als bomFormat angeben.",
        "ru": "В документе поле bomFormat должно иметь значение CycloneDX.",
    },
    "finding.specVersion": {
        "en": "BSI profile {profile} requires CycloneDX {minimum} or newer. Supported here: {supported}.",
        "de": "Das BSI-Profil {profile} erfordert CycloneDX {minimum} oder neuer. Hier unterstützt: {supported}.",
        "ru": "Профиль BSI {profile} требует CycloneDX {minimum} или новее. Здесь поддерживаются: {supported}.",
    },
    "finding.serialNumberInvalid": {
        "en": "If supplied, serialNumber must use the urn:uuid format.",
        "de": "Falls angegeben, muss serialNumber das Format urn:uuid verwenden.",
        "ru": "Если serialNumber указан, он должен иметь формат urn:uuid.",
    },
    "finding.timestampMissing": {
        "en": "Add the required SBOM creation timestamp to metadata.timestamp.",
        "de": "Fügen Sie den erforderlichen SBOM-Erstellungszeitpunkt in metadata.timestamp ein.",
        "ru": "Добавьте обязательное время создания SBOM в metadata.timestamp.",
    },
    "finding.sbomCreatorMissing": {
        "en": "Declare the SBOM creator in metadata.manufacturer with an email or URL.",
        "de": "Geben Sie den SBOM-Ersteller in metadata.manufacturer mit E-Mail oder URL an.",
        "ru": "Укажите создателя SBOM в metadata.manufacturer с email или URL.",
    },
    "finding.rootComponentMissing": {
        "en": "Describe the primary component in metadata.component.",
        "de": "Beschreiben Sie die primäre Komponente in metadata.component.",
        "ru": "Опишите основной компонент в metadata.component.",
    },
    "finding.embeddedVulnerabilities": {
        "en": "Remove embedded vulnerability data from the SBOM; publish it separately as VEX or CSAF.",
        "de": "Entfernen Sie eingebettete Schwachstellendaten aus der SBOM und veröffentlichen Sie sie separat als VEX oder CSAF.",
        "ru": "Удалите данные об уязвимостях из SBOM и публикуйте их отдельно в формате VEX или CSAF.",
    },
    "finding.schemaValidation": {
        "en": "CycloneDX {version} schema validation failed: {reason}",
        "de": "Die CycloneDX-{version}-Schemavalidierung ist fehlgeschlagen: {reason}",
        "ru": "Проверка по схеме CycloneDX {version} не пройдена: {reason}",
    },
    "finding.componentRefMissing": {
        "en": "{component} has no bom-ref for stable dependency relationships.",
        "de": "{component} hat keine bom-ref für stabile Abhängigkeitsbeziehungen.",
        "ru": "У компонента {component} отсутствует bom-ref для устойчивых связей зависимостей.",
    },
    "finding.componentRefDuplicate": {
        "en": "{component} reuses duplicate bom-ref {reference}.",
        "de": "{component} verwendet die doppelte bom-ref {reference}.",
        "ru": "Компонент {component} повторно использует bom-ref {reference}.",
    },
    "finding.componentNameMissing": {
        "en": "A component name is required.",
        "de": "Ein Komponentenname ist erforderlich.",
        "ru": "Необходимо указать имя компонента.",
    },
    "finding.componentVersionMissing": {
        "en": "{component} has no required version.",
        "de": "Für {component} fehlt die erforderliche Version.",
        "ru": "У компонента {component} отсутствует обязательная версия.",
    },
    "finding.componentCreatorMissing": {
        "en": "{component} needs a manufacturer email or URL as component creator.",
        "de": "{component} benötigt eine Hersteller-E-Mail oder URL als Komponentenersteller.",
        "ru": "Для {component} нужен email или URL производителя как создателя компонента.",
    },
    "finding.dependencyNodeMissing": {
        "en": "{component} must appear in the dependency graph, even with an empty dependsOn list.",
        "de": "{component} muss im Abhängigkeitsgraphen erscheinen, auch mit einer leeren dependsOn-Liste.",
        "ru": "{component} должен присутствовать в графе зависимостей, даже с пустым dependsOn.",
    },
    "finding.completenessMissing": {
        "en": "Declare dependency completeness for {component} in compositions.",
        "de": "Deklarieren Sie die Vollständigkeit der Abhängigkeiten für {component} in compositions.",
        "ru": "Укажите полноту зависимостей для {component} в compositions.",
    },
    "finding.distributionLicenseMissing": {
        "en": "{component} needs a distribution license expression with acknowledgement concluded.",
        "de": "{component} benötigt einen Distributionslizenzausdruck mit acknowledgement concluded.",
        "ru": "Для {component} нужна лицензия распространения с expression и acknowledgement concluded.",
    },
    "finding.filenameMissing": {
        "en": "Add bsi:component:filename for {component} when it is fully described and not only logical or identified.",
        "de": "Fügen Sie bsi:component:filename für {component} hinzu, wenn die Komponente vollständig beschrieben und nicht nur logisch oder identifiziert ist.",
        "ru": "Добавьте bsi:component:filename для {component}, если это полностью описанный, а не только логический или идентифицированный компонент.",
    },
    "finding.filenamePath": {
        "en": "bsi:component:filename for {component} must be a filename, not a path.",
        "de": "bsi:component:filename für {component} muss ein Dateiname und kein Pfad sein.",
        "ru": "bsi:component:filename для {component} должен быть именем файла, а не путём.",
    },
    "finding.sha512Missing": {
        "en": "Add a SHA-512 hash to the distribution external reference for {component} when fully described.",
        "de": "Fügen Sie für {component} einen SHA-512-Hash zur distribution-Referenz hinzu, wenn die Komponente vollständig beschrieben ist.",
        "ru": "Для полностью описанного {component} добавьте SHA-512 в distribution external reference.",
    },
    "finding.executableMissing": {
        "en": "Add bsi:component:executable for {component} when fully described.",
        "de": "Fügen Sie bsi:component:executable für {component} hinzu, wenn die Komponente vollständig beschrieben ist.",
        "ru": "Для полностью описанного {component} добавьте bsi:component:executable.",
    },
    "finding.executableInvalid": {
        "en": "Executable value {value} for {component} must be executable or non-executable.",
        "de": "Der executable-Wert {value} für {component} muss executable oder non-executable sein.",
        "ru": "Значение executable {value} для {component} должно быть executable или non-executable.",
    },
    "finding.archiveMissing": {
        "en": "Add bsi:component:archive for {component} when fully described.",
        "de": "Fügen Sie bsi:component:archive für {component} hinzu, wenn die Komponente vollständig beschrieben ist.",
        "ru": "Для полностью описанного {component} добавьте bsi:component:archive.",
    },
    "finding.archiveInvalid": {
        "en": "Archive value {value} for {component} must be archive or no archive.",
        "de": "Der archive-Wert {value} für {component} muss archive oder no archive sein.",
        "ru": "Значение archive {value} для {component} должно быть archive или no archive.",
    },
    "finding.structuredMissing": {
        "en": "Add bsi:component:structured for {component} when fully described.",
        "de": "Fügen Sie bsi:component:structured für {component} hinzu, wenn die Komponente vollständig beschrieben ist.",
        "ru": "Для полностью описанного {component} добавьте bsi:component:structured.",
    },
    "finding.structuredInvalid": {
        "en": "Structured value {value} for {component} must be structured or unstructured.",
        "de": "Der structured-Wert {value} für {component} muss structured oder unstructured sein.",
        "ru": "Значение structured {value} для {component} должно быть structured или unstructured.",
    },
}


def localize_finding(finding: ValidationFinding, language: str) -> str:
    language = language if language in SUPPORTED_LANGUAGES else "en"
    templates = MESSAGES.get(finding.message_key, {})
    template = templates.get(language) or templates.get("en") or finding.message_key
    return template.format_map(_SafeParams(finding.params))


def localized_report(report: AnalysisReport, language: str) -> dict[str, Any]:
    language = language if language in SUPPORTED_LANGUAGES else "en"
    payload = report.model_dump(mode="json", by_alias=True)
    payload["language"] = language
    payload["findings"] = [
        {
            **finding.model_dump(mode="json", by_alias=True),
            "message": localize_finding(finding, language),
        }
        for finding in report.findings
    ]
    return payload


class _SafeParams(dict[str, Any]):
    def __missing__(self, key: str) -> str:
        return f"{{{key}}}"
