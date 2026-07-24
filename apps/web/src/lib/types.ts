export type Language = 'en' | 'de' | 'ru';
export type Tab = 'findings' | 'components' | 'vulnerabilities';
export type FindingLevel = 'error' | 'warning' | 'info';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface ComplianceProfile {
	id: string;
	version: string;
	format: string;
	mappingVersion: string;
	minimumSpecVersion: string;
	referenceUrl: string;
}

export interface Finding {
	code: string;
	level: FindingLevel;
	messageKey: string;
	message?: string;
	path: string;
	params: Record<string, unknown>;
}

export interface Component {
	bomRef: string | null;
	name: string;
	version: string | null;
	componentType: string;
	group: string | null;
	purl: string | null;
	creator: string | null;
	filename: string | null;
	licenses: string[];
	hashes: string[];
	executable: string | null;
	archive: string | null;
	structured: string | null;
	relationship: string;
}

export interface Vulnerability {
	id: string;
	componentRef: string | null;
	componentName: string;
	installedVersion: string | null;
	severity: Severity;
	cvssScore: number | null;
	cvssVector: string | null;
	severitySource: string | null;
	summary: string;
	aliases: string[];
	fixedVersions: string[];
	references: string[];
	source: string;
}

export interface AnalysisSummary {
	componentCount: number;
	scannableComponentCount: number;
	scannedComponentCount: number;
	scanLimit: number;
	scanTruncated: boolean;
	vulnerabilityDataComplete: boolean;
	vulnerabilityDetailFailureCount: number;
	vulnerabilityDetailLimit: number;
	vulnerabilityDetailsTruncated: boolean;
	vulnerabilityCount: number;
	criticalCount: number;
	highCount: number;
	mediumCount: number;
	lowCount: number;
	unknownCount: number;
	validationErrorCount: number;
	validationWarningCount: number;
	complianceScore: number;
	riskScore: number;
}

export interface AnalysisReport {
	id: string;
	createdAt: string;
	provider: string;
	profile: ComplianceProfile;
	document: {
		filename: string;
		bomFormat: string | null;
		specVersion: string | null;
		serialNumber: string | null;
		timestamp: string | null;
		rootComponent: string | null;
	};
	summary: AnalysisSummary;
	findings: Finding[];
	components: Component[];
	vulnerabilities: Vulnerability[];
	language?: Language;
}

export interface HistoryItem {
	id: string;
	createdAt: string;
	filename: string;
	provider: string;
	componentCount: number;
	vulnerabilityCount: number;
	complianceScore: number;
	riskScore: number;
}
