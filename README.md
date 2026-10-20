# Youssef Bouaouina — interactive portfolio

A static, dependency-free portfolio with three browser demos:

- **ATOR** — an interactive replay of a real ATOR incident investigation: 6 detections, 3 endpoints, a reconstructed 5-stage ATT&CK chain, evidence drawers and the generated report.
- **MediTrack** — a medication inventory and adherence demo backed by `localStorage`; sample data only, not medical advice.
- **devopsNIDS** — an animated Jenkins pipeline with success and injected-failure paths.

**Live site:** https://youssefbouaouina.github.io/portfolio/

## Structure

```
index.html                 All sections, demos, dialogs and inline SVG icons
assets/css/style.css       Responsive dark SOC-inspired design
assets/js/app.js           Demo logic: filters, dialogs, charts, localStorage, pipeline
assets/data/ator.json      Sanitised ATOR demo dataset (API hashes and paths removed)
assets/data/meditrack.json Sample medication and interaction data
assets/files/              ATOR report PDF/STIX/Navigator + EN/FR CVs
```

## Run locally

```powershell
python -m http.server 8080
```

Then open http://localhost:8080. The site does not require a build step or a backend.

## Data provenance

The ATOR dataset was exported from a real local end-to-end verification run (20/20 checks). Identifiers, API hashes and server paths were stripped before publication. The site is a replay: actions such as containment approval are presented as read-only evidence, not live operations. MediTrack data is fictional, and the devopsNIDS runner simulates the repository's Jenkins stages in the browser.

No analytics, cookies or third-party scripts.
