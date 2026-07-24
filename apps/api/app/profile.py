from app.models import ComplianceProfile

PROFILE_ID = "BSI TR-03183-2"
PROFILE_VERSION = "2.1.0"
PROFILE_FORMAT = "CycloneDX JSON"
PROFILE_MAPPING_VERSION = "1.6"
MINIMUM_CYCLONEDX_VERSION = "1.6"
SUPPORTED_CYCLONEDX_VERSIONS = {"1.6", "1.7"}
PROFILE_REFERENCE_URL = (
    "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/"
    "TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf"
    "?__blob=publicationFile&v=5"
)


def supported_profile() -> ComplianceProfile:
    return ComplianceProfile(
        id=PROFILE_ID,
        version=PROFILE_VERSION,
        format=PROFILE_FORMAT,
        mapping_version=PROFILE_MAPPING_VERSION,
        minimum_spec_version=MINIMUM_CYCLONEDX_VERSION,
        reference_url=PROFILE_REFERENCE_URL,
    )


def profile_label() -> str:
    return f"{PROFILE_ID} v{PROFILE_VERSION}"
