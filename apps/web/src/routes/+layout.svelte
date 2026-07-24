<script lang="ts">
	import favicon from '$lib/assets/favicon.svg';
	import '../app.css';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<meta
		name="description"
		content="SupplyGuard validates CycloneDX SBOMs against BSI TR-03183-2 v2.1.0 and checks packages for known vulnerabilities."
	/>
	<meta name="theme-color" content="#102321" />
	<title>SupplyGuard · SBOM Security Workspace</title>
</svelte:head>

{@render children()}
