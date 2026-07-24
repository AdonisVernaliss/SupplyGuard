<script lang="ts">
	import { env } from '$env/dynamic/public';
	import { onMount } from 'svelte';
	import { languageNames, translate, type MessageKey } from '$lib/i18n';
	import type {
		AnalysisReport,
		HistoryItem,
		Language,
		Tab
	} from '$lib/types';

	const API_BASE = (env.PUBLIC_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
	const languages: Language[] = ['en', 'de', 'ru'];

	let language = $state<Language>('en');
	let selectedFile = $state<File | null>(null);
	let provider = $state<'osv' | 'demo'>('osv');
	let loading = $state(false);
	let dragging = $state(false);
	let error = $state('');
	let report = $state<AnalysisReport | null>(null);
	let history = $state<HistoryItem[]>([]);
	let activeTab = $state<Tab>('findings');
	let fileInput = $state<HTMLInputElement>();

	function t(key: MessageKey): string {
		return translate(language, key);
	}

	onMount(() => {
		const saved = localStorage.getItem('supplyguard-language');
		const browserLanguage = navigator.language.toLowerCase();
		if (saved === 'en' || saved === 'de' || saved === 'ru') {
			language = saved;
		} else if (browserLanguage.startsWith('de')) {
			language = 'de';
		} else if (browserLanguage.startsWith('ru')) {
			language = 'ru';
		}
		void loadHistory();
	});

	async function setLanguage(next: Language) {
		language = next;
		localStorage.setItem('supplyguard-language', next);
		document.documentElement.lang = next;
		if (report) {
			await localizeReport(report.id);
		}
	}

	function chooseFile(file: File | undefined) {
		if (!file) return;
		selectedFile = file;
		error = '';
	}

	function fileChanged(event: Event) {
		const input = event.currentTarget as HTMLInputElement;
		chooseFile(input.files?.[0]);
	}

	function dropped(event: DragEvent) {
		event.preventDefault();
		dragging = false;
		chooseFile(event.dataTransfer?.files[0]);
	}

	async function runAnalysis() {
		if (!selectedFile || loading) return;
		const body = new FormData();
		body.append('file', selectedFile);
		await analyze(`/api/v1/analyses?provider=${provider}`, {
			method: 'POST',
			body
		});
	}

	async function runDemo() {
		if (loading) return;
		await analyze('/api/v1/analyses/demo', { method: 'POST' });
	}

	async function analyze(path: string, init: RequestInit) {
		loading = true;
		error = '';
		try {
			const response = await fetch(`${API_BASE}${path}`, init);
			if (!response.ok) {
				const payload = await response.json().catch(() => null);
				throw new Error(payload?.detail || t('invalidResponse'));
			}
			const raw = (await response.json()) as AnalysisReport;
			report = raw;
			activeTab = raw.findings.length ? 'findings' : 'vulnerabilities';
			await localizeReport(raw.id);
			await loadHistory();
			setTimeout(() => document.querySelector('#report')?.scrollIntoView({ behavior: 'smooth' }), 80);
		} catch (caught) {
			error = caught instanceof TypeError ? t('apiUnavailable') : String((caught as Error).message);
		} finally {
			loading = false;
		}
	}

	async function localizeReport(id: string) {
		try {
			const response = await fetch(`${API_BASE}/api/v1/analyses/${id}/report?lang=${language}`);
			if (response.ok) report = (await response.json()) as AnalysisReport;
		} catch {
			// Keep the already returned report when only localization is unavailable.
		}
	}

	async function loadHistory() {
		try {
			const response = await fetch(`${API_BASE}/api/v1/analyses?limit=8`);
			if (response.ok) history = (await response.json()) as HistoryItem[];
		} catch {
			// The upload card remains usable and will surface a focused connection error.
		}
	}

	async function openHistory(id: string) {
		loading = true;
		error = '';
		try {
			const response = await fetch(`${API_BASE}/api/v1/analyses/${id}`);
			if (!response.ok) throw new Error(t('invalidResponse'));
			report = (await response.json()) as AnalysisReport;
			activeTab = 'findings';
			await localizeReport(id);
			setTimeout(() => document.querySelector('#report')?.scrollIntoView({ behavior: 'smooth' }), 50);
		} catch (caught) {
			error = caught instanceof TypeError ? t('apiUnavailable') : String((caught as Error).message);
		} finally {
			loading = false;
		}
	}

	function resetAnalysis() {
		report = null;
		selectedFile = null;
		error = '';
		fileInput && (fileInput.value = '');
		window.scrollTo({ top: 0, behavior: 'smooth' });
	}

	function formatDate(value: string): string {
		const locales: Record<Language, string> = { en: 'en-GB', de: 'de-DE', ru: 'ru-RU' };
		return new Intl.DateTimeFormat(locales[language], {
			dateStyle: 'medium',
			timeStyle: 'short'
		}).format(new Date(value));
	}

	function relationshipLabel(value: string): string {
		if (value === 'root' || value === 'direct' || value === 'transitive' || value === 'unknown') {
			return t(value);
		}
		return value;
	}
</script>

<svelte:head>
	<html lang={language}></html>
</svelte:head>

<header class="topbar">
	<div class="shell topbar-inner">
		<a class="brand" href="#top" aria-label="SupplyGuard">
			<span class="brand-mark" aria-hidden="true">
				<svg viewBox="0 0 24 24" fill="none">
					<path d="M12 3 19 6v5c0 4.7-2.8 8.2-7 10-4.2-1.8-7-5.3-7-10V6l7-3Z" stroke="currentColor" stroke-width="1.8"/>
					<path d="m8.6 12 2.1 2.1 4.8-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
				</svg>
			</span>
			<span class="brand-copy">
				<strong>SupplyGuard</strong>
				<span>{t('tagline')}</span>
			</span>
		</a>

		<div class="top-actions">
			<nav class="nav-links" aria-label="Primary navigation">
				<a class="nav-link" href="#top">{t('navAnalyze')}</a>
				<a class="nav-link" href="#history">{t('navHistory')}</a>
			</nav>
			<div class="language-switch" aria-label="Language">
				{#each languages as item}
					<button
						class:active={language === item}
						type="button"
						aria-pressed={language === item}
						onclick={() => setLanguage(item)}
					>{languageNames[item]}</button>
				{/each}
			</div>
		</div>
	</div>
</header>

<main id="top">
	<section class="shell hero">
		<div class="hero-copy">
			<div class="eyebrow">{t('heroEyebrow')}</div>
			<h1>{t('heroTitle')}<span>{t('heroAccent')}</span></h1>
			<p>{t('heroBody')}</p>
			<a
				class="profile-strip"
				href="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=5"
				target="_blank"
				rel="noreferrer"
			>
				<span class="profile-icon">✓</span>
				<div>
					<small>{t('profile')}</small>
					<strong>BSI TR-03183-2 v2.1.0 · {t('profileMapping')} 1.6</strong>
				</div>
			</a>
		</div>

		<div class="upload-card">
			<div class="card-heading">
				<h2>{t('uploadTitle')}</h2>
				<span class="secure-label"><span class="secure-dot"></span>JSON only</span>
			</div>
			<div
				class="dropzone"
				class:dragging
				role="button"
				tabindex="0"
				ondragover={(event) => {
					event.preventDefault();
					dragging = true;
				}}
				ondragleave={() => (dragging = false)}
				ondrop={dropped}
				onkeydown={(event) => {
					if (event.key === 'Enter' || event.key === ' ') fileInput?.click();
				}}
			>
				<div>
					<span class="drop-icon" aria-hidden="true">
						<svg viewBox="0 0 24 24" fill="none">
							<path d="M12 16V4m0 0L7.5 8.5M12 4l4.5 4.5M5 14v4a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>
						</svg>
					</span>
					<strong>{selectedFile?.name || t('uploadBody')}</strong>
					<p>{selectedFile ? `${(selectedFile.size / 1024).toFixed(1)} KiB` : t('uploadHint')}</p>
					<label class="file-button">
						{t('chooseFile')}
						<input
							bind:this={fileInput}
							type="file"
							accept=".json,.cdx.json,application/json"
							onchange={fileChanged}
						/>
					</label>
				</div>
			</div>
			<div class="upload-controls">
				<select class="provider-select" bind:value={provider} aria-label="Vulnerability provider">
					<option value="osv">{t('liveData')}</option>
					<option value="demo">{t('demoData')}</option>
				</select>
				<button
					class="primary-button"
					type="button"
					disabled={!selectedFile || loading}
					onclick={runAnalysis}
				>
					{#if loading}<span class="spinner"></span>{/if}
					{loading ? t('analyzing') : t('analyze')}
				</button>
			</div>
			<div class="demo-row">
				<span>{t('demoHint')}</span>
				<button class="demo-button" type="button" disabled={loading} onclick={runDemo}>
					{t('tryDemo')} →
				</button>
			</div>
		</div>
	</section>

	{#if error}
		<div class="shell">
			<div class="error-banner" role="alert">
				<span aria-hidden="true">!</span>
				<div><strong>{t('errorTitle')}</strong>{error}</div>
			</div>
		</div>
	{/if}

	{#if report}
		<section class="dashboard" id="report">
			<div class="shell">
				<div class="section-header">
					<div class="section-title">
						<small>{t('statusReady')}</small>
						<h2>{t('report')}</h2>
						<p>{report.document.filename} · {formatDate(report.createdAt)}</p>
					</div>
					<div class="report-actions">
						<button class="ghost-button" type="button" onclick={resetAnalysis}>{t('newAnalysis')}</button>
						<a
							class="secondary-button"
							href={`${API_BASE}/api/v1/analyses/${report.id}/report?lang=${language}`}
							download
						>{t('download')} ↓</a>
					</div>
				</div>

				<div class="metrics-grid">
					<div class="metric-card score-card">
						<div class="score-ring" style={`--score: ${report.summary.complianceScore}%`}>
							<strong>{report.summary.complianceScore}</strong>
						</div>
						<div class="score-copy">
							<small>{t('compliance')}</small>
							<strong>{report.profile.id}</strong>
							<span>v{report.profile.version} · CDX {report.profile.mappingVersion}</span>
						</div>
					</div>
					<div class="metric-card score-card">
						<div class="score-ring risk" style={`--score: ${report.summary.riskScore}%`}>
							<strong>{report.summary.riskScore}</strong>
						</div>
						<div class="score-copy">
							<small>{t('risk')}</small>
							<strong>{report.provider}</strong>
							<span>{report.summary.scannedComponentCount}/{report.summary.scannableComponentCount} {t('scanned').toLowerCase()}</span>
						</div>
					</div>
					<div class="metric-card plain-metric">
						<small>{t('components')}</small>
						<div class="metric-value">{report.summary.componentCount}</div>
						<div class="metric-foot"><span class="metric-dot"></span>{report.summary.scannedComponentCount}/{report.summary.scannableComponentCount} {t('scanned')}</div>
					</div>
					<div class="metric-card plain-metric">
						<small>{t('vulnerabilities')}</small>
						<div class="metric-value">{report.summary.vulnerabilityCount}</div>
						<div class="metric-foot"><span class="metric-dot red"></span>{report.summary.criticalCount} {t('critical')}</div>
					</div>
					<div class="metric-card plain-metric">
						<small>{t('errors')}</small>
						<div class="metric-value">{report.summary.validationErrorCount}</div>
						<div class="metric-foot"><span class="metric-dot red"></span>BSI v{report.profile.version}</div>
					</div>
					<div class="metric-card plain-metric">
						<small>{t('warnings')}</small>
						<div class="metric-value">{report.summary.validationWarningCount}</div>
						<div class="metric-foot"><span class="metric-dot amber"></span>CycloneDX {report.document.specVersion}</div>
					</div>
				</div>

				{#if report.summary.scanTruncated || !report.summary.vulnerabilityDataComplete}
					<div class="coverage-notice" role="status">
						<span aria-hidden="true">!</span>
						<div>
							<strong>{t('partialResults')}</strong>
							{#if report.summary.scanTruncated}<p>{t('componentLimitNotice')} ({report.summary.scannedComponentCount}/{report.summary.scannableComponentCount}, limit {report.summary.scanLimit})</p>{/if}
							{#if !report.summary.vulnerabilityDataComplete}<p>{t('osvPartialNotice')} ({report.summary.vulnerabilityDetailFailureCount}{#if report.summary.vulnerabilityDetailsTruncated} · limit {report.summary.vulnerabilityDetailLimit}{/if})</p>{/if}
						</div>
					</div>
				{/if}

				<div class="results-panel">
					<div class="tabs" role="tablist">
						<button class="tab" class:active={activeTab === 'findings'} type="button" onclick={() => (activeTab = 'findings')}>
							{t('findings')} <span class="tab-count">{report.findings.length}</span>
						</button>
						<button class="tab" class:active={activeTab === 'components'} type="button" onclick={() => (activeTab = 'components')}>
							{t('components')} <span class="tab-count">{report.components.length}</span>
						</button>
						<button class="tab" class:active={activeTab === 'vulnerabilities'} type="button" onclick={() => (activeTab = 'vulnerabilities')}>
							{t('vulnerabilities')} <span class="tab-count">{report.vulnerabilities.length}</span>
						</button>
					</div>

					<div class="result-content">
						{#if activeTab === 'findings'}
							{#if report.findings.length}
								{#each report.findings as finding}
									<div class="finding-row">
										<span class:info={finding.level === 'info'} class:error={finding.level === 'error'} class="level-icon">
											{finding.level === 'error' ? '×' : finding.level === 'warning' ? '!' : 'i'}
										</span>
										<div class="finding-main">
											<strong>{finding.message || finding.messageKey}</strong>
											<div class="finding-meta"><span>{t('path')}: {finding.path}</span></div>
										</div>
										<span class="code-pill">{finding.code}</span>
									</div>
								{/each}
							{:else}
								<div class="empty-state"><div><span>✓</span><p>{t('noFindings')}</p></div></div>
							{/if}
						{:else if activeTab === 'components'}
							<div class="table-scroll">
								<table class="data-table">
									<thead>
										<tr>
											<th>{t('component')}</th><th>{t('version')}</th><th>{t('relationship')}</th>
											<th>{t('creator')}</th><th>{t('file')}</th><th>{t('license')}</th>
										</tr>
									</thead>
									<tbody>
										{#each report.components as component}
											<tr>
												<td><span class="component-name">{component.name}<code>{component.purl || component.bomRef || '—'}</code></span></td>
												<td>{component.version || '—'}</td>
												<td><span class:root={component.relationship === 'root'} class="relation-pill">{relationshipLabel(component.relationship)}</span></td>
												<td>{component.creator || '—'}</td>
												<td>{component.filename || '—'}</td>
												<td>{component.licenses.join(', ') || '—'}</td>
											</tr>
										{/each}
									</tbody>
								</table>
							</div>
						{:else}
							{#if report.vulnerabilities.length}
								{#each report.vulnerabilities as vulnerability}
									<div class="vulnerability-row">
										<span class={`severity-pill ${vulnerability.severity}`}>{vulnerability.severity}</span>
										<div class="vulnerability-main">
											<strong>{vulnerability.id} · {vulnerability.componentName} {vulnerability.installedVersion || ''}</strong>
											<p>{vulnerability.summary}</p>
											<div class="vulnerability-meta">
												<span>{t('fixed')}: {vulnerability.fixedVersions.join(', ') || '—'}</span>
												<span>{t('source')}: {vulnerability.source}</span>
												{#if vulnerability.cvssScore !== null}<span>CVSS {vulnerability.cvssScore} · {vulnerability.severitySource}</span>{/if}
											</div>
										</div>
										{#if vulnerability.references[0]}
											<a class="code-pill" href={vulnerability.references[0]} target="_blank" rel="noreferrer">↗</a>
										{/if}
									</div>
								{/each}
							{:else}
								<div class="empty-state"><div><span>✓</span><p>{t('noVulnerabilities')}</p></div></div>
							{/if}
						{/if}
					</div>
				</div>
			</div>
		</section>
	{/if}

	<section class="history-section" id="history">
		<div class="shell">
			<div class="section-header">
				<div class="section-title">
					<small>SupplyGuard</small>
					<h2>{t('recent')}</h2>
				</div>
			</div>
			{#if history.length}
				<div class="history-list">
					{#each history as item}
						<button class="history-item" type="button" onclick={() => openHistory(item.id)}>
							<span class="history-name"><strong>{item.filename}</strong><small>{formatDate(item.createdAt)}</small></span>
							<span class="history-stat"><strong>{item.complianceScore}</strong><small>{t('compliance')}</small></span>
							<span class="history-stat"><strong>{item.riskScore}</strong><small>{t('risk')}</small></span>
							<span class="history-stat"><strong>{item.componentCount}</strong><small>{t('components')}</small></span>
							<span class="history-arrow">→</span>
						</button>
					{/each}
				</div>
			{:else}
				<div class="empty-state"><div><span>⌁</span><p>{t('noHistory')}</p></div></div>
			{/if}
		</div>
	</section>
</main>

<footer class="footer">
	<div class="shell footer-inner">
		<span>{t('disclaimer')}</span>
		<a
			href="https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TR03183/BSI-TR-03183-2_v2_1_0.pdf?__blob=publicationFile&v=5"
			target="_blank"
			rel="noreferrer"
		>BSI TR-03183-2 v2.1.0 ↗</a>
	</div>
</footer>
