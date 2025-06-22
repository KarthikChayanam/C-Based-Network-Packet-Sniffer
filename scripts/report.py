#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

csv_path   = Path("log/output.csv")
report_dir = Path("reports")
report_dir.mkdir(exist_ok=True)

df = pd.read_csv(csv_path, parse_dates=["Timestamp"])

# 2‑A Packets‑per‑second
pps = df.set_index("Timestamp").resample("1S").size()
plt.figure()
pps.plot()
plt.title("Packets per Second")
plt.ylabel("pps")
plt.xlabel("Time")
plt.savefig(report_dir / "pps.png", bbox_inches="tight")

# 2‑B Protocol Distribution
proto_counts = df["Protocol"].value_counts()
plt.figure()
proto_counts.plot(kind="bar")
plt.title("Protocol Distribution")
plt.ylabel("Packets")
plt.savefig(report_dir / "proto_dist.png", bbox_inches="tight")

# 2‑C Top Talkers
top = (
    df.groupby("Src IP")["Length"]
      .sum()
      .sort_values(ascending=False)
      .head(10)
)
top.to_csv(report_dir / "top_hosts.csv", header=["Bytes"])

# 2‑D Simple HTML Report
html = f"""
<html><body>
<h1>Sniffer Summary</h1>
<h2>Packets per Second</h2>
<img src="pps.png"><br>
<h2>Protocol Distribution</h2>
<img src="proto_dist.png"><br>
<h2>Top Talkers (bytes sent)</h2>
{top.to_frame().to_html()}
</body></html>
"""
(report_dir / "sniff-summary.html").write_text(html)
print("Report written to", report_dir)
