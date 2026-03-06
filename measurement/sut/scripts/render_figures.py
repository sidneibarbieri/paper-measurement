#!/usr/bin/env python3
"""
Render TikZ figure templates from measured JSON outputs.
This removes manual numeric edits in paper figures.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RESULTS = Path(__file__).resolve().parent / "results"
FIGS = ROOT / "ACM CCS - Paper 2" / "figs"


def cdf_points(values, step=0.1):
    xs = [round(i * step, 1) for i in range(int(1 / step) + 1)]
    n = len(values) or 1
    ys = []
    for x in xs:
        ys.append(sum(1 for v in values if v <= x) / n)
    return xs, ys


def fmt(v):
    if isinstance(v, float):
        return f"{v:.1f}".rstrip("0").rstrip(".")
    return str(v)


def coord(v):
    return f"{v:.2f}"


def render_coverage(d):
    c = d["coverage_chart"]
    e, m, i, cap, f = c["enterprise"], c["mobile"], c["ics"], c["capec"], c["fight"]
    return f"""\\definecolor{{acmBlue}}{{HTML}}{{1F77B4}}
\\definecolor{{acmTeal}}{{HTML}}{{009E73}}
\\definecolor{{acmSand}}{{HTML}}{{D55E00}}
\\definecolor{{acmGrid}}{{HTML}}{{D9DDE2}}
\\begin{{tikzpicture}}[x=0.48cm,y=0.03cm,font=\\footnotesize]
  \\draw[->] (0,0) -- (17.2,0) node[right] {{Corpus}};
  \\draw[->] (0,0) -- (0,124) node[above] {{\\%}};
  \\foreach \\yy in {{0,20,40,60,80,100}} {{
    \\draw[acmGrid] (0,\\yy) -- (16.8,\\yy);
    \\node[left] at (0,\\yy) {{\\yy}};
  }}
  \\fill[acmBlue]   (1.0,0) rectangle (1.8,{e['platform']});
  \\fill[acmTeal]   (1.9,0) rectangle (2.7,{e['software_link']});
  \\fill[acmSand]   (2.8,0) rectangle (3.6,{e['cve_link']});
  \\node[above] at (1.4,{e['platform']}) {{{fmt(e['platform'])}}};
  \\node[above] at (2.3,{e['software_link']}) {{{fmt(e['software_link'])}}};
  \\node[above] at (3.2,{coord(max(1.7, e['cve_link'] + 0.4))}) {{{fmt(e['cve_link'])}}};
  \\fill[acmBlue]   (4.0,0) rectangle (4.8,{m['platform']});
  \\fill[acmTeal]   (4.9,0) rectangle (5.7,{m['software_link']});
  \\fill[acmSand]   (5.8,0) rectangle (6.6,{m['cve_link']});
  \\node[above] at (4.4,{m['platform']}) {{{fmt(m['platform'])}}};
  \\node[above] at (5.3,{m['software_link']}) {{{fmt(m['software_link'])}}};
  \\fill[acmBlue]   (7.0,0) rectangle (7.8,{i['platform']});
  \\fill[acmTeal]   (7.9,0) rectangle (8.7,{i['software_link']});
  \\fill[acmSand]   (8.8,0) rectangle (9.6,{i['cve_link']});
  \\node[above] at (7.4,{i['platform']}) {{{fmt(i['platform'])}}};
  \\node[above] at (8.3,{i['software_link']}) {{{fmt(i['software_link'])}}};
  \\node[above] at (9.2,{coord(max(1.7, i['cve_link'] + 0.4))}) {{{fmt(i['cve_link'])}}};
  \\fill[acmBlue!40]   (10.0,0) rectangle (10.8,{cap['platform']});
  \\fill[acmTeal!40]   (10.9,0) rectangle (11.7,{cap['software_link']});
  \\fill[acmSand!40]   (11.8,0) rectangle (12.6,{cap['cve_link']});
  \\node[above,text=gray] at (11.3,2) {{{fmt(cap['platform'])}}};
  \\fill[acmBlue]   (13.0,0) rectangle (13.8,{f['platform']});
  \\fill[acmTeal]   (13.9,0) rectangle (14.7,{f['software_link']});
  \\fill[acmSand]   (14.8,0) rectangle (15.6,{f['cve_link']});
  \\node[above] at (13.4,{f['platform']}) {{{fmt(f['platform'])}}};
  \\node[above] at (14.3,{f['software_link']}) {{{fmt(f['software_link'])}}};
  \\node[above] at (15.2,{coord(max(1.7, f['cve_link'] + 0.4))}) {{{fmt(f['cve_link'])}}};
  \\node at (2.3,-8) {{Enterprise}};
  \\node at (5.3,-8) {{Mobile}};
  \\node at (8.3,-8) {{ICS}};
  \\node at (11.3,-8) {{CAPEC}};
  \\node at (14.3,-8) {{FiGHT}};
  \\node[anchor=north west,fill=white,fill opacity=0.95,text opacity=1,inner sep=2.2pt] at (10.9,121.6) {{
    \\begin{{tabular}}{{@{{}}l@{{}}}}
      \\textcolor{{acmBlue}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ $\\rho_P$: platform\\\\[1pt]
      \\textcolor{{acmTeal}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ $\\rho_S$: software\\\\[1pt]
      \\textcolor{{acmSand}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ $\\rho_V$: CVE
    \\end{{tabular}}
  }};
\\end{{tikzpicture}}
"""


def render_software_specificity(d):
    s = d["software_specificity"]
    return f"""\\definecolor{{acmGrayFill}}{{HTML}}{{B7BDC5}}
\\definecolor{{acmTeal}}{{HTML}}{{009E73}}
\\definecolor{{acmBlue}}{{HTML}}{{1F77B4}}
\\definecolor{{acmGrid}}{{HTML}}{{D9DDE2}}
\\begin{{tikzpicture}}[x=0.073cm,y=0.55cm,font=\\footnotesize]
  \\draw[->] (0,0) -- (112,0) node[right] {{\\% of software objects ($N={s['total_software']}$)}};
  \\foreach \\x in {{0,20,40,60,80,100}} {{
    \\draw[acmGrid] (\\x,0) -- (\\x,7.0);
    \\node[below] at (\\x,0) {{\\x}};
  }}
  \\fill[acmGrayFill] (0,2.4) rectangle ({s['no_version_no_cpe_pct']},5.2);
  \\fill[acmTeal] ({s['no_version_no_cpe_pct']},2.4) rectangle (100,5.2);
  \\node at ({s['no_version_no_cpe_pct']/2:.2f},3.8) {{No version, no CPE ({s['no_version_no_cpe']})}};
  \\node[anchor=west] at (100.5,3.8) {{{fmt(s['version_no_cpe_pct'])}\\%}};
  \\node at ({s['no_version_no_cpe_pct']/2:.2f},5.9) {{{fmt(s['no_version_no_cpe_pct'])}\\%}};
  \\node[anchor=west] at (100.5,5.9) {{v.~only ({s['version_no_cpe']})}};
  \\node[anchor=north west,fill=white,fill opacity=0.95,text opacity=1,inner sep=2.2pt] at (55.0,6.9) {{
    \\begin{{tabular}}{{@{{}}l@{{}}}}
      \\textcolor{{acmGrayFill}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ No version, no CPE\\\\[1pt]
      \\textcolor{{acmTeal}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ Textual version only\\\\[1pt]
      \\textcolor{{acmBlue}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ CPE (0 objects)
    \\end{{tabular}}
  }};
\\end{{tikzpicture}}
"""


def render_cve_location(d):
    c = d["cve_location"]
    s_pct = round(100 * c["structured_count"] / c["total"], 1) if c["total"] else 0
    f_pct = round(100 * c["freetext_only_count"] / c["total"], 1) if c["total"] else 0
    return f"""\\definecolor{{acmBlue}}{{HTML}}{{1F77B4}}
\\definecolor{{acmRust}}{{HTML}}{{D55E00}}
\\definecolor{{acmGrid}}{{HTML}}{{D9DDE2}}
\\begin{{tikzpicture}}[x=0.073cm,y=0.68cm,font=\\footnotesize]
  \\draw[->] (0,0) -- (112,0) node[right] {{CVE count ($N={c['total']}$)}};
  \\foreach \\x in {{0,5,10,15,20,25}} {{
    \\draw[acmGrid] (\\x*4,0) -- (\\x*4,8.2);
    \\node[below] at (\\x*4,0) {{\\x}};
  }}
  \\node[anchor=east] at (-1.0,5.8) {{Structured fields}};
  \\node[anchor=east] at (-1.0,2.6) {{Free-text only}};
  \\fill[acmBlue] (0,5.0) rectangle ({c['structured_count']*4},6.6);
  \\fill[acmRust]  (0,1.8) rectangle ({c['freetext_only_count']*4},3.4);
  \\node[anchor=west] at ({c['structured_count']*4 + 1.0},5.8) {{{c['structured_count']} ({s_pct}\\%)}};
  \\node[anchor=west] at ({c['freetext_only_count']*4 + 1.0},2.6) {{{c['freetext_only_count']} ({f_pct}\\%)}};
\\end{{tikzpicture}}
"""


def render_jaccard(d):
    j = d["jaccard_cdf"]
    xs, ys_sw = cdf_points(j["software_only_distances"])
    _, ys_sc = cdf_points(j["software_cve_distances"])
    pts_sw = " -- ".join(f"({x:.2f},{y:.3f})" for x, y in zip(xs, ys_sw))
    pts_sc = " -- ".join(f"({x:.2f},{y:.3f})" for x, y in zip(xs, ys_sc))
    confused = next((y for x, y in zip(xs, ys_sc) if abs(x - j["delta_threshold"]) < 1e-9), 0.0)
    return f"""\\definecolor{{acmBlue}}{{HTML}}{{1F77B4}}
\\definecolor{{acmTeal}}{{HTML}}{{009E73}}
\\definecolor{{acmGrid}}{{HTML}}{{D9DDE2}}
\\definecolor{{acmDelta}}{{HTML}}{{8A8F99}}
\\begin{{tikzpicture}}[x=7.6cm,y=4.7cm,font=\\footnotesize]
  \\draw[->] (0,0) -- (1.05,0) node[right] {{Nearest-neighbor Jaccard distance}};
  \\draw[->] (0,0) -- (0,1.05) node[above] {{Cumulative fraction of groups}};
  \\foreach \\x in {{0,0.2,0.4,0.6,0.8,1.0}} {{
    \\draw[acmGrid] (\\x,0) -- (\\x,1.0);
    \\node[below] at (\\x,0) {{\\x}};
  }}
  \\foreach \\y in {{0,0.2,0.4,0.6,0.8,1.0}} {{
    \\draw[acmGrid] (0,\\y) -- (1.0,\\y);
    \\node[left] at (0,\\y) {{\\y}};
  }}
  \\draw[line width=0.9pt,acmBlue] {pts_sw};
  \\draw[line width=0.9pt,acmTeal,densely dashed] {pts_sc};
  \\draw[densely dashed,acmDelta] ({j['delta_threshold']},0) -- ({j['delta_threshold']},1.0);
  \\node[anchor=south west,text=acmDelta] at ({j['delta_threshold'] + 0.005:.3f},0.10) {{$\\delta={j['delta_threshold']}$}};
  \\node[anchor=north west,text=acmDelta] at ({j['delta_threshold'] + 0.005:.3f},0.085) {{{round(100*confused,1)}\\% confused}};
  \\node[anchor=north west,fill=white,fill opacity=0.95,text opacity=1,inner sep=2.2pt] at (0.56,0.98) {{
    \\begin{{tabular}}{{@{{}}l@{{}}}}
      \\textcolor{{acmBlue}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ Software only\\\\[1pt]
      \\textcolor{{acmTeal}}{{\\rule{{0.95em}}{{0.72em}}}}\\ \\ Software + CVE
    \\end{{tabular}}
  }};
\\end{{tikzpicture}}
"""


def main():
    d = json.loads((RESULTS / "figures_data.json").read_text(encoding="utf-8"))
    FIGS.mkdir(parents=True, exist_ok=True)
    (FIGS / "coverage_template.tex").write_text(render_coverage(d), encoding="utf-8")
    (FIGS / "software_specificity_template.tex").write_text(render_software_specificity(d), encoding="utf-8")
    (FIGS / "cve_location_template.tex").write_text(render_cve_location(d), encoding="utf-8")
    (FIGS / "jaccard_cdf_template.tex").write_text(render_jaccard(d), encoding="utf-8")
    print("Rendered 4 figure templates from measured JSON.")


if __name__ == "__main__":
    main()
