```
python auto-scripts/workflow_evaluation.py --out-dir out --csv eval.csv --pricing .\auto-scripts\pricing.csv
[pricing override] .\auto-scripts\pricing.csv: input_tokens=0.435, output_tokens=0.87, cache_read_tokens=0.003625
wrote 194 rows (74 CVEs) -> eval.csv [pricing: .\auto-scripts\pricing.csv]
grand total: turns=3786 in=6877688 out=1914846 cache_read=170482304 cache_write=0 total_tokens=179274838 cost=$5.2757 wall=412.6min

per-step stats (real runs; steps 2-3 exclude gated):
  step 1 crs-retrieve-analyze (n=74):
    turns         avg=      27.9  min=      20.0  max=      37.0
    dur_min       avg=      2.72  min=      1.62  max=      9.16
    dur_api_min   avg=      2.68  min=      1.59  max=      9.12
    total_tokens  avg=   1285515  min=    612445  max=   1989919
    cost_usd      avg=    0.0389  min=    0.0289  max=    0.0782
  step 2 crs-variant-gen (n=23):
    turns         avg=      29.1  min=      21.0  max=      37.0
    dur_min       avg=      2.87  min=      1.40  max=      5.66
    dur_api_min   avg=      2.83  min=      1.37  max=      5.60
    total_tokens  avg=   1140630  min=    537533  max=   2613757
    cost_usd      avg=    0.0392  min=    0.0254  max=    0.0713
  step 3 crs-rule-author (n=23):
    turns         avg=      45.7  min=      29.0  max=      81.0
    dur_min       avg=      6.31  min=      2.54  max=     12.86
    dur_api_min   avg=      6.26  min=      2.50  max=     12.72
    total_tokens  avg=   2517925  min=   1007254  max=   6217629
    cost_usd      avg=    0.0650  min=    0.0370  max=    0.1096

per-CVE stats (full pipeline per CVE):
  all (n=74):
    turns         avg=      51.2  min=      20.0  max=     142.0
    dur_min       avg=      5.58  min=      1.62  max=     21.65
    dur_api_min   avg=      5.51  min=      1.59  max=     21.49
    total_tokens  avg=   2422633  min=    612445  max=   9009129
    cost_usd      avg=    0.0713  min=    0.0289  max=    0.2351
  covered (n=12):
    turns         avg=      27.1  min=      24.0  max=      29.0
    dur_min       avg=      2.34  min=      1.62  max=      2.90
    dur_api_min   avg=      2.31  min=      1.59  max=      2.86
    total_tokens  avg=   1196949  min=    612445  max=   1468407
    cost_usd      avg=    0.0367  min=    0.0289  max=    0.0422
  in-scope (n=23):
    turns         avg=     102.4  min=      85.0  max=     142.0
    dur_min       avg=     12.35  min=      6.68  max=     21.65
    dur_api_min   avg=     12.22  min=      6.57  max=     21.49
    total_tokens  avg=   4963146  min=   3281109  max=   9009129
    cost_usd      avg=    0.1469  min=    0.1077  max=    0.2351
  gated (n=39):
    turns         avg=      28.3  min=      20.0  max=      36.0
    dur_min       avg=      2.58  min=      1.69  max=      3.34
    dur_api_min   avg=      2.54  min=      1.66  max=      3.30
    total_tokens  avg=   1301515  min=    620656  max=   1861828
    cost_usd      avg=    0.0373  min=    0.0301  max=    0.0441
```