# BSI TR-03183-2 profile

## Supported profile

SupplyGuard targets **BSI TR-03183-2 v2.1.0** (20 August 2025).

The supported profile is a first-class API value:

```json
{
  "id": "BSI TR-03183-2",
  "version": "2.1.0",
  "format": "CycloneDX JSON",
  "mappingVersion": "1.6",
  "minimumSpecVersion": "1.6"
}
```

The constants live in `apps/api/app/profile.py`. Changing the profile requires changing those constants, the rule implementation, tests, sample, documentation, and UI label together.

Official source: [BSI TR-03183-2 v2.1.0 (PDF)](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=5)

## Format scope

- CycloneDX JSON `1.6` is the normative mapping basis documented by BSI.
- SupplyGuard accepts CycloneDX JSON `1.6` and `1.7`.
- SPDX 3.0.1 is part of the BSI guideline but is not implemented in this MVP.
- The uploaded document is never modified.

## Implemented checks

### SBOM

- `bomFormat` is `CycloneDX`;
- `specVersion` is supported;
- `metadata.timestamp` exists;
- the SBOM creator is represented by an email or URL in `metadata.manufacturer`;
- `metadata.component` describes the primary component;
- a supplied `serialNumber` uses `urn:uuid`;
- vulnerability data is not embedded in the SBOM.

### Components

The primary component and all nested `components` are traversed. Checks cover:

- component creator through manufacturer email or URL;
- component name and version;
- stable, unique `bom-ref`;
- a dependency-graph node for every `bom-ref`, including empty leaf nodes;
- dependency completeness in `compositions`;
- a distribution licence as `licenses[].expression` with `acknowledgement: concluded`;
- the actual filename in `bsi:component:filename`;
- a SHA-512 hash in an `externalReferences` item of type `distribution`;
- `bsi:component:executable` with `executable` or `non-executable`;
- `bsi:component:archive` with `archive` or `no archive`;
- `bsi:component:structured` with `structured` or `unstructured`.

## Logical, identified, and referenced components

BSI v2.1.0 distinguishes fully described, logical, identified, and BOM-referenced components. CycloneDX does not provide a single unambiguous flag for this classification. SupplyGuard therefore:

- treats creator, name, version, licences, dependency nodes, and completeness as strong profile requirements;
- reports missing file-specific fields and SHA-512 as warnings, because those fields do not apply to every logical or merely identified component;
- reports invalid supplied BSI property values as errors.

This prevents false claims of non-conformance while still making missing fields visible. A future version can add an explicit analysis policy for the intended SBOM level of detail.

## Vulnerability separation

TR-03183-2 says an SBOM must not contain vulnerability information because it changes independently from the component inventory. SupplyGuard follows that model:

- the uploaded SBOM remains an inventory document;
- live OSV results are stored in the SupplyGuard analysis report;
- embedded `vulnerabilities` in the uploaded CycloneDX document create an error finding;
- future export formats may include CSAF or CycloneDX VEX as separate documents.

## Scoring

The score is a transparent product heuristic, not a BSI-defined score:

- error: −12 points;
- warning: −4 points;
- informational finding: −1 point;
- minimum: 0, maximum: 100.

Consumers that require a binary policy should evaluate finding codes and levels rather than the score alone.

## Limitations

- No official BSI conformance or certification is claimed.
- JSON Schema validation is not yet a separate stage.
- Licence-expression syntax is not parsed beyond checking the mapped structure.
- Hash content presence is checked; SupplyGuard does not download the artefact to recompute it.
- OSV matching currently requires a package URL.
- External BOM references are not resolved recursively.
