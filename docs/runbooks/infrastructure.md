# Infrastructure

## Search C2IntelFeeds

1. Open [Infrastructure](http://127.0.0.1:8000/infrastructure) and select
   **Refresh C2 Feeds**. The toolkit makes three keyless GET requests to
   fixed CSV URLs on the publisher's GitHub repository and stores the
   resulting snapshot in `data/cti.db`. If any feed fails, the page shows
   the error and keeps the previous snapshot.
2. Enter an IP, domain, or part of a publisher label. Defanged values
   such as `example[.]org` work. Search runs in local SQLite.
3. **Publisher Checked** displays the source's C2 IP and filtered domain
   feeds. **Unverified** shows its separately published IP matches.
   The label in both views is the publisher's claim. Open the CSV
   source for provenance and corroborate a match independently.
4. The three files represent a seven-day observation window. The
   page shows when the toolkit fetched them. The CSVs do not give
   a timestamp for each sighting.

Standalone refresh and offline verification on Windows:

```powershell
Invoke-WebRequest -Method POST -Uri 'http://127.0.0.1:8000/infrastructure/refresh-c2'
.\.venv\Scripts\python.exe -B -m unittest tests.test_infrastructure
```

Source data belongs to drb-ra and is distributed under CC BY-NC-SA 4.0.
The toolkit uses it locally for non-commercial research. The wider windows,
configuration exports, and fingerprint hunts are tracked in the roadmap.
[Source repository](https://github.com/drb-ra/C2IntelFeeds)
[Licence](https://github.com/drb-ra/C2IntelFeeds/blob/master/License.md)
[Publisher dashboard](https://drb-ra.github.io/c2intel-web/).
