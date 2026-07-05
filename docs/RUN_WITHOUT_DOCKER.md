# Running Elasticsearch without Docker

Aura DFIR does **not** use or require Docker. The application is a plain Python web app that
talks to Elasticsearch over HTTP at whatever URL you put in `ES_URL` (default
`http://localhost:9200`). You just need an Elasticsearch instance reachable there — how you run
it is entirely your choice.

Elasticsearch itself is a Java service, but the official distribution **bundles its own Java**,
so you do **not** need to install a JDK.

## Using the executable? It handles all of this for you

If you run the packaged `AuraDFIR.exe`, you don't need any of the steps below. On its **first
launch** it asks how to get Elasticsearch:

- point it at an **existing** ES install folder (one that contains `bin\elasticsearch.bat`) —
  nothing is re-downloaded;
- point it at a **URL** of an ES you already run; or
- press **Enter** to download & set it up once (~600 MB).

It remembers the choice in `es_config.json` and **auto-starts Elasticsearch on every later
launch** (no prompt, no re-download), stopping it again when you close the app.
`AuraDFIR.exe --reset-es` clears the saved choice. The rest of this page is for running from
source (the venv workflow).

## Option A — the helper script (easiest, from source)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_elasticsearch.ps1
```

It downloads Elasticsearch (~600 MB, once) into `.elasticsearch\` inside the repo, configures it
for single-node local dev with security disabled, and starts it at `http://localhost:9200`.
Leave the window open; press Ctrl+C to stop. Re-running it starts instantly (no re-download).

## Option B — do it manually

1. Download the Windows ZIP from
   <https://www.elastic.co/downloads/elasticsearch> (e.g. `elasticsearch-8.13.4-windows-x86_64.zip`).
2. Unzip it anywhere, e.g. `C:\elasticsearch-8.13.4`.
3. Edit `config\elasticsearch.yml` and add:
   ```yaml
   discovery.type: single-node
   xpack.security.enabled: false
   ```
4. (Optional) cap memory: set an environment variable before starting —
   `set ES_JAVA_OPTS=-Xms512m -Xmx512m`
5. Start it:
   ```powershell
   C:\elasticsearch-8.13.4\bin\elasticsearch.bat
   ```
6. Confirm it's up: open <http://localhost:9200> — you should get a JSON banner.

## Option C — use an Elasticsearch you already have

Point Aura DFIR at any existing cluster by editing `.env`:

```
ES_URL=https://your-es-host:9200
ES_USER=elastic
ES_PASSWORD=your-password
```

## Verifying

With ES running, the Aura DFIR dashboard shows the cluster status (green/yellow) instead of
"unreachable". You can also check directly:

```powershell
Invoke-WebRequest http://localhost:9200 -UseBasicParsing | Select-Object -ExpandProperty Content
```

## Notes

- **Kibana is optional** — Aura DFIR renders its own charts. If you want Kibana's Dev Tools for
  ad-hoc queries, download it the same way from elastic.co and point it at `http://localhost:9200`.
- **RAM**: the helper caps the heap at 512 MB, which is fine for triage-sized cases. Raise it
  (`-HeapSize 1g`) for very large logs.
- **Production**: turn security back on and set `ES_USER`/`ES_PASSWORD` in `.env`.
