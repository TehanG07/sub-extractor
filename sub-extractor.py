import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import subprocess, os, threading, re
from concurrent.futures import ThreadPoolExecutor

# ---------------- UTILS ----------------
def run(cmd):
    return subprocess.getoutput(cmd)

def log(msg):
    output.insert(tk.END, msg + "\n")
    output.see(tk.END)

# ---------------- CONFIG ----------------
CVE_MAP = {
    "nginx": ("CVE-2021-23017", "MEDIUM"),
    "apache": ("CVE-2021-44790", "MEDIUM"),
    "wordpress": ("Multiple WP CVEs", "HIGH"),
    "php": ("CVE-2019-11043", "HIGH"),
    "jenkins": ("CVE-2023-27898", "CRITICAL"),
    "tomcat": ("CVE-2020-1938", "CRITICAL"),
}

TAKEOVER_PROVIDERS = {
    "amazonaws.com": "AWS S3",
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "azurewebsites.net": "Azure",
    "fastly.net": "Fastly"
}

SEVERITY_SCORE = {"LOW": 2.0, "MEDIUM": 4.5, "HIGH": 7.5, "CRITICAL": 9.0}

SAFE_TAGS = "misconfiguration,exposures,default-logins,technologies,headers"

# ---------------- MAIN ----------------
def start():
    domain = entry.get().strip()
    if not domain:
        messagebox.showerror("Error", "Enter domain")
        return
    threading.Thread(target=scan, args=(domain,), daemon=True).start()

def scan(domain):
    wd = f"recon_{domain}"
    ev = f"{wd}/evidence"
    os.makedirs(f"{ev}/screenshots", exist_ok=True)

    log("🔍 Subdomain discovery...")
    run(f"subfinder -d {domain} -silent > {wd}/subs.txt")
    run(f"assetfinder --subs-only {domain} >> {wd}/subs.txt")
    run(f"sort -u {wd}/subs.txt > {wd}/final_subs.txt")

    log("🌐 httpx scan...")
    run(
        f"httpx -l {wd}/final_subs.txt "
        f"-sc -td -cdn -title -server "
        f"-silent > {wd}/httpx.txt"
    )

    log("🛰️ Passive DNS takeover validation...")
    takeover_hits, passive_dns = passive_takeover_check(f"{wd}/final_subs.txt", ev)

    log("🧠 Recon analysis + CVSS scoring...")
    analyzed = analyze_results(wd, takeover_hits)

    log("🔗 Nuclei SAFE scan...")
    run(
        f"nuclei -l {wd}/final_subs.txt "
        f"-severity low,medium,high "
        f"-tags {SAFE_TAGS} "
        f"-silent -o {ev}/nuclei_raw.txt"
    )

    nuclei_hits = reduce_nuclei_fp(ev)

    log("📸 Screenshots (high-risk only)...")
    targets = collect_targets(analyzed, nuclei_hits)
    if targets:
        with open(f"{ev}/targets.txt", "w") as f:
            f.write("\n".join(targets))
        run(
            f"gowitness file -f {ev}/targets.txt "
            f"--destination {ev}/screenshots --disable-db"
        )

    bundle_evidence(wd, analyzed, nuclei_hits)
    log("✅ FINAL MODE COMPLETE 😈")

    # Show Risk Heatmap
    show_heatmap(analyzed)

# ---------------- PASSIVE TAKEOVER ----------------
def passive_takeover_check(subfile, ev):
    hits, passive_log = [], []

    def check(sub):
        sub = sub.strip()
        cname = run(f"dig +short CNAME {sub}").strip()
        a = run(f"dig +short A {sub}").strip()
        if cname and not a:
            for k, v in TAKEOVER_PROVIDERS.items():
                if k in cname:
                    return f"{sub} | Provider:{v} | CNAME:{cname} | A:NONE"
        return None

    with ThreadPoolExecutor(max_workers=20) as exe:
        for r in exe.map(check, open(subfile)):
            if r:
                hits.append(r)
                passive_log.append(r)

    if passive_log:
        with open(f"{ev}/passive_dns_takeovers.txt", "w") as f:
            f.write("\n".join(passive_log))

    return hits, passive_log

# ---------------- ANALYSIS + CVSS ----------------
def analyze_results(wd, takeover_hits):
    results = []

    for line in open(f"{wd}/httpx.txt", errors="ignore"):
        low = line.lower()
        sev, cve = "LOW", "-"
        exploit = "-"
        score = SEVERITY_SCORE["LOW"]

        for tech, (cve_id, s) in CVE_MAP.items():
            if tech in low:
                sev, cve = s, cve_id
                score = SEVERITY_SCORE[s]

        if re.search(r"\badmin|dev|staging\b", low):
            score += 0.7

        if cve.startswith("CVE") and sev in ("HIGH", "CRITICAL"):
            exploit = lookup_exploit(cve)
            if exploit != "-":
                score += 1.0

        score = min(score, 10.0)
        results.append(f"{sev} | Risk:{score:.1f}/10 | CVE:{cve} | Exploit:{exploit} | {line.strip()}")

    for t in takeover_hits:
        results.append(f"CRITICAL | Risk:9.8/10 | TAKEOVER | Exploit:MANUAL | {t}")

    with open(f"{wd}/killer_report.txt", "w") as f:
        f.write("\n".join(results))

    return results

# ---------------- EXPLOIT DB ----------------
def lookup_exploit(cve):
    out = run(f"searchsploit {cve}")
    if "No Results" in out:
        return "-"
    m = re.search(r"exploitdb.com/exploits/\d+", out)
    return m.group(0) if m else "AVAILABLE"

# ---------------- NUCLEI FP REDUCER ----------------
def reduce_nuclei_fp(ev):
    clean, seen = [], set()
    raw = f"{ev}/nuclei_raw.txt"
    if not os.path.exists(raw):
        return clean

    for l in open(raw, errors="ignore"):
        if "[info]" in l.lower(): continue
        host = l.split(" ")[-1]
        if host in seen: continue
        seen.add(host)
        clean.append(l.strip())

    with open(f"{ev}/nuclei_hits.txt", "w") as f:
        f.write("\n".join(clean))
    return clean

# ---------------- TARGET FILTER ----------------
def collect_targets(analyzed, nuclei):
    t = set()
    for l in analyzed:
        if "Risk:" in l:
            try:
                if float(re.search(r"Risk:(\d+\.\d)", l).group(1)) >= 7.0:
                    m = re.search(r"(https?://\S+)", l)
                    if m: t.add(m.group(1))
            except: pass
    for n in nuclei:
        m = re.search(r"(https?://\S+)", n)
        if m: t.add(m.group(1))
    return sorted(t)

# ---------------- EVIDENCE ----------------
def bundle_evidence(wd, analyzed, nuclei):
    ev = f"{wd}/evidence"
    os.makedirs(ev, exist_ok=True)
    with open(f"{ev}/summary.txt", "w") as f:
        f.write("=== HIGH RISK (CVSS ≥7) ===\n")
        for l in analyzed:
            if "Risk:" in l and float(re.search(r"Risk:(\d+\.\d)", l).group(1)) >= 7.0:
                f.write(l + "\n")
        f.write("\n=== NUCLEI SAFE ===\n")
        for n in nuclei:
            f.write(n + "\n")

# ---------------- RISK HEATMAP GUI ----------------
def show_heatmap(analyzed):
    heat = tk.Toplevel(root)
    heat.title("📊 Risk Heatmap")
    heat.geometry("800x500")
    
    tree = ttk.Treeview(heat, columns=("subdomain","risk","severity"), show="headings")
    tree.heading("subdomain", text="Subdomain")
    tree.heading("risk", text="Risk Score")
    tree.heading("severity", text="Severity")
    tree.pack(fill="both", expand=True)

    # Colors for severity
    def get_color(score):
        if score >= 9: return "#ff1a1a"    # Red
        elif score >= 7: return "#ff9933"  # Orange
        elif score >= 4: return "#ffff66"  # Yellow
        return "#66ff66"                   # Green

    for l in analyzed:
        m_r = re.search(r"Risk:(\d+\.\d)", l)
        if m_r:
            score = float(m_r.group(1))
            severity = l.split(" | ")[0]
            subdomain = l.split(" | ")[-1]
            tree.insert("", "end", values=(subdomain, f"{score:.1f}", severity), tags=(severity,))
            tree.tag_configure(severity, background=get_color(score))

# ---------------- GUI ----------------
root = tk.Tk()
root.title("ReconX – FINAL MODE ∞ 😈")
root.geometry("1050x700")

tk.Label(root, text="Target Domain", font=("Arial", 12)).pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack()

tk.Button(
    root,
    text="😈 START FINAL MODE ∞",
    bg="#111",
    fg="#0f0",
    font=("Arial", 12),
    command=start
).pack(pady=10)

output = scrolledtext.ScrolledText(root, height=12)
output.pack(fill="both", expand=True, padx=10, pady=5)

root.mainloop()
