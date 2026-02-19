# BIGQUERY: package-campaigns lookup (temporary)

This is a temporary note file created to hold BigQuery query examples and usage notes for the `kam193/package-campaigns` index. Delete this file when you no longer need it.

Purpose
- Record safe, read-only BigQuery queries to recover historical PyPI distribution metadata for package names listed in the package-campaigns index.

Important safety note
- Do not download or build untrusted packages on your host. Use an isolated VM or disposable container for any artifact fetching or unpacking.

Example SQL (replace `<PACKAGENAME>` with the package name):

```sql
SELECT *
FROM `bigquery-public-data.pypi.distribution_metadata`
WHERE name LIKE '<PACKAGENAME>'
LIMIT 10;
```

bq CLI example (read-only):

```bash
bq query --nouse_legacy_sql \
  "SELECT name, version, url, upload_time \
   FROM `bigquery-public-data.pypi.distribution_metadata` \
   WHERE name = 'badpack' \
   LIMIT 10"
```

Batch workflow suggestions
- Download `package-campaigns` JSON locally (it contains lists of package names).
- Use a small script to iterate names and run parameterized queries (via the `bq` CLI or the BigQuery API), writing results to a CSV/JSON report.
- Only collect metadata (name, version, upload_time, url). Avoid downloading URLs unless you will analyze them in a fully isolated environment.

Caveats
- PyPI removal/unindexing may remove actual artifacts while metadata can remain in public datasets — availability varies.
- BigQuery contains historical metadata snapshots; presence in the dataset does not guarantee the associated artifact is still hosted by PyPI or package mirrors.

This file is intentionally brief — move these notes into a more permanent docs page or delete when no longer needed.
