
import os, json, yaml, asyncio, threading, queue
import tkinter as tk, tkinter.ttk as ttk, tkinter.messagebox as mbox, tkinter.filedialog as fd
import customtkinter as ctk
from engine import run_scan, request_stop

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".darkhunter")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.yaml")

class App(ctk.CTk):
    def _discover_plugins(self):
        plugins=[]
        try:
            for f in os.listdir('plugins'):
                if f.endswith('.py') and f not in ['__init__.py','base_plugin.py']:
                    name=f[:-3]
                    if name not in plugins:
                        plugins.append(name)
        except Exception:
            pass
        return sorted(plugins)

    def __init__(self):
        super().__init__()
        self.title("DarkHunter — created by DarkSec/Null_Lyfe")
        self.geometry("1200x780")
        ctk.set_appearance_mode("Dark"); ctk.set_default_color_theme("blue")
        self.gui_queue=queue.Queue(); self.findings_data={}
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._build()
        self._load_persisted_settings()
        self.after(100, self._process_queue)

    def _build(self):
        self.toolbar = ctk.CTkFrame(self); self.toolbar.pack(fill="x")
        ctk.CTkButton(self.toolbar, text="Stop", command=lambda: (request_stop(), self.log_message("🛑 Stop requested"))).pack(side="left", padx=6, pady=6)
        ctk.CTkLabel(self.toolbar, text="Profile").pack(side="left", padx=(12,4))
        self.profile=tk.StringVar(value="Full")
        ctk.CTkOptionMenu(self.toolbar, variable=self.profile, values=["Quick","Full","Recon","Safe Passive"]).pack(side="left", padx=4)

        self.panes = ttk.PanedWindow(self, orient="horizontal"); self.panes.pack(fill="both", expand=True)
        self.left=ctk.CTkFrame(self.panes); self.right=ctk.CTkFrame(self.panes)
        self.panes.add(self.left, weight=1); self.panes.add(self.right, weight=2)

        self.tabs_left = ctk.CTkTabview(self.left); self.tabs_left.pack(fill="both", expand=True, padx=10, pady=10)
        tabs = self.tabs_left
        tabs.add("Target"); tabs.add("Scope"); tabs.add("Plugins"); tabs.add("Config"); tabs.add("Marketplace"); tabs.add("Self-Test")

        t=tabs.tab("Target")
        self.target=ctk.CTkEntry(t, placeholder_text="https://example.com"); self.target.pack(fill="x", padx=6, pady=6)
        ctk.CTkLabel(t,text="Targets (one per line)").pack(anchor="w", padx=6)
        self.targets_box=ctk.CTkTextbox(t, height=120); self.targets_box.pack(fill="x", padx=6, pady=6)
        self.conc=tk.IntVar(value=10); ctk.CTkLabel(t,text="Concurrency").pack(anchor="w", padx=6)
        ctk.CTkSlider(t, from_=1,to=100, number_of_steps=99, variable=self.conc).pack(fill="x", padx=6, pady=(0,6))
        self.rate=tk.IntVar(value=5); ctk.CTkLabel(t,text="Rate Limit (req/s)").pack(anchor="w", padx=6)
        ctk.CTkSlider(t, from_=0,to=50, number_of_steps=50, variable=self.rate).pack(fill="x", padx=6, pady=(0,6))

        s=tabs.tab("Scope")
        ctk.CTkLabel(s,text="Allow (one per line, supports * and regex:/.../)").pack(anchor="w", padx=6)
        self.allow=ctk.CTkTextbox(s, height=100); self.allow.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(s,text="Deny (deny wins)").pack(anchor="w", padx=6)
        self.deny=ctk.CTkTextbox(s, height=90); self.deny.pack(fill="x", padx=6, pady=4)

        p=tabs.tab("Plugins")
        self._build_plugins_tab(p)

        # --- Config tab ---
        c=tabs.tab("Config")
        ctk.CTkLabel(c, text="HackerOne API (id:token)").pack(anchor="w", padx=6, pady=(8,0))
        self.h1_key=ctk.CTkEntry(c, placeholder_text="id:token"); self.h1_key.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(c, text="Bugcrowd API (username:token)").pack(anchor="w", padx=6, pady=(8,0))
        self.bc_key=ctk.CTkEntry(c, placeholder_text="user:token"); self.bc_key.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(c, text="OAST Server (default oast.pro)").pack(anchor="w", padx=6, pady=(8,0))
        self.oast_server=ctk.CTkEntry(c, placeholder_text="oast.pro"); self.oast_server.pack(fill="x", padx=6, pady=4)
        ctk.CTkLabel(c, text="OAST Mode (simple_domain / interactsh_api)").pack(anchor="w", padx=6)
        self.oast_mode=tk.StringVar(value="simple_domain")
        ctk.CTkOptionMenu(c, variable=self.oast_mode, values=["simple_domain","interactsh_api"]).pack(fill="x", padx=6, pady=4)
        row=ctk.CTkFrame(c); row.pack(fill="x", padx=6, pady=6)
        ctk.CTkButton(row, text="Save YAML", command=self.save_yaml).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Load YAML", command=self.load_yaml).pack(side="left", padx=4)

        # --- Self-Test tab ---
        st = tabs.tab("Self-Test")
        ctk.CTkLabel(st, text="Run built-in diagnostics to verify your environment.").pack(anchor="w", padx=6, pady=(8,0))
        ctk.CTkButton(st, text="Run Diagnostics", command=self.run_self_test).pack(anchor="w", padx=6, pady=6)
        self.selftest_out = ctk.CTkTextbox(st, height=240)
        self.selftest_out.pack(fill="both", expand=True, padx=6, pady=6)

    # --- Plugins: discovery + UI ---
    def _discover_plugins(self):
        plugins_dir = os.path.join(os.path.dirname(__file__), "plugins")
        names=[]
        try:
            for f in os.listdir(plugins_dir):
                if not f.endswith(".py"): 
                    continue
                if f == "__init__.py":
                    continue
                names.append(f[:-3])
        except Exception as e:
            self.log_message(f"Plugin discovery error: {e}")
        return sorted(names)

    def _build_plugins_tab(self, tab):
        # Keep prior selections if any
        prev = {k:v.get() for k,v in getattr(self, "plugins_vars", {}).items()} if hasattr(self, "plugins_vars") else {}
        self.plugins_vars = {}
        for child in tab.winfo_children():
            child.destroy()

        row_top = ctk.CTkFrame(tab); row_top.pack(fill="x", padx=6, pady=(6,2))
        ctk.CTkButton(row_top, text="Refresh", command=lambda:self._build_plugins_tab(tab)).pack(side="left", padx=(0,6))
        ctk.CTkLabel(row_top, text="Discovered plugins in ./plugins").pack(side="left")

        container = ctk.CTkScrollableFrame(tab, height=360)
        container.pack(fill="both", expand=True, padx=6, pady=6)

        for name in self._discover_plugins():
            var = tk.BooleanVar(value=prev.get(name, True if name in ["check_headers","check_ssrf_oast","check_xss_reflected","check_graphql_detect"] else False))
            self.plugins_vars[name] = var
            ctk.CTkCheckBox(container, text=name, variable=var).pack(anchor="w", padx=6, pady=2)

        tabs2 = ctk.CTkTabview(self.right); tabs2.pack(fill="both", expand=True, padx=10, pady=10)
        tabs2.add("Live Log"); tabs2.add("Findings"); tabs2.add("Export")
        self.log = ctk.CTkTextbox(tabs2.tab("Live Log")); self.log.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(tabs2.tab("Findings"), columns=("Severity","Title"), show="headings")
        self.tree.heading("Severity", text="Severity"); self.tree.heading("Title", text="Title")
        self.tree.column("Severity", width=100, anchor="center"); self.tree.pack(fill="both", expand=True, pady=(0,6))
        self.evidence = ctk.CTkTextbox(tabs2.tab("Findings"), height=150); self.evidence.pack(fill="x")
        self.tree.bind("<<TreeviewSelect>>", self._show_evidence)

        ex=tabs2.tab("Export")
        ctk.CTkButton(ex, text="Export ALL to HTML", command=self.export_all_html).pack(fill="x", padx=10, pady=6)
        ctk.CTkButton(ex, text="Export ALL to DOCX", command=self.export_all_docx).pack(fill="x", padx=10, pady=6)
        ctk.CTkButton(ex, text="Export ALL to PDF", command=self.export_all_pdf).pack(fill="x", padx=10, pady=6)
        ctk.CTkButton(ex, text="Export Selected (Bug Bounty PDF)", command=self.export_selected_bug_pdf).pack(fill="x", padx=10, pady=6)

        self.start=ctk.CTkButton(self.left, text="Start Scan", command=self._start_scan); self.start.pack(fill="x", padx=10, pady=8)

    # Persistence
    def _load_persisted_settings(self):
        try:
            if os.path.exists(CONFIG_FILE):
                data=yaml.safe_load(open(CONFIG_FILE,"r",encoding="utf-8"))
                if data.get("target"): self.target.delete(0,"end"); self.target.insert(0,data["target"])
                if data.get("targets"): self.targets_box.delete("1.0","end"); self.targets_box.insert("1.0","\n".join(data["targets"]))
                sc=data.get("scope",{}) or {}
                if "allow" in sc: self.allow.delete("1.0","end"); self.allow.insert("1.0","\n".join(sc.get("allow",[])))
                if "deny" in sc: self.deny.delete("1.0","end"); self.deny.insert("1.0","\n".join(sc.get("deny",[])))
                if "plugins_to_run" in data:
                    for k,v in self.plugins_vars.items(): v.set(k in set(data["plugins_to_run"]))
                self.h1_key.delete(0,"end"); self.h1_key.insert(0,(data.get("h1_api_key") or ""))
                self.bc_key.delete(0,"end"); self.bc_key.insert(0,(data.get("bc_api_key") or ""))
                if "oast" in data:
                    o=data["oast"]; self.oast_server.delete(0,"end"); self.oast_server.insert(0,o.get("server","oast.pro"))
                    self.oast_mode.set(o.get("mode","simple_domain"))
                self.log_message("Loaded settings from %s" % CONFIG_FILE)
        except Exception as e:
            self.log_message("Settings load failed: %s" % e)

    def _persist_settings(self):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            yaml.safe_dump(self._collect_config(), open(CONFIG_FILE,"w",encoding="utf-8"), sort_keys=False)
        except Exception as e:
            self.log_message("Settings save failed: %s" % e)

    def log_message(self, msg):
        self.log.insert("end", msg + "\n"); self.log.see("end")

    def save_yaml(self):
        cfg=self._collect_config()
        p=fd.asksaveasfilename(title="Save YAML", defaultextension=".yaml")
        if not p: return
        yaml.safe_dump(cfg, open(p,"w",encoding="utf-8"), sort_keys=False)
        self.log_message("Saved YAML to: %s" % p)

    def load_yaml(self):
        p=fd.askopenfilename(title="Load YAML", filetypes=[("YAML","*.yaml *.yml")])
        if not p: return
        data=yaml.safe_load(open(p,"r",encoding="utf-8"))
        if data.get("target"): self.target.delete(0,"end"); self.target.insert(0,data["target"])
        if data.get("targets"):
            self.targets_box.delete("1.0","end"); self.targets_box.insert("1.0","\n".join(data["targets"]))
        sc=data.get("scope",{}) or {}
        if "allow" in sc: self.allow.delete("1.0","end"); self.allow.insert("1.0","\n".join(sc.get("allow",[])))
        if "deny" in sc: self.deny.delete("1.0","end"); self.deny.insert("1.0","\n".join(sc.get("deny",[])))
        if "plugins_to_run" in data:
            for k,v in self.plugins_vars.items(): v.set(k in set(data["plugins_to_run"]))
        self.h1_key.delete(0,"end"); self.h1_key.insert(0,(data.get("h1_api_key") or ""))
        self.bc_key.delete(0,"end"); self.bc_key.insert(0,(data.get("bc_api_key") or ""))
        if "oast" in data:
            o=data["oast"]; self.oast_server.delete(0,"end"); self.oast_server.insert(0,o.get("server","oast.pro"))
            self.oast_mode.set(o.get("mode","simple_domain"))
        self.log_message("Loaded YAML from: %s" % p)

    def _collect_config(self):
        def lines(tbox): return [l.strip() for l in tbox.get("1.0","end").splitlines() if l.strip()]
        enabled=[k for k,v in self.plugins_vars.items() if v.get()]
        return {"target": self.target.get().strip(), "targets": lines(self.targets_box),
                "concurrency": int(self.conc.get()), "rate_limit": int(self.rate.get()), "headers": {},
                "scope": {"allow": lines(self.allow), "deny": lines(self.deny)},
                "plugins_to_run": enabled, "profile": self.profile.get(),
                "h1_api_key": self.h1_key.get().strip(), "bc_api_key": self.bc_key.get().strip(),
                "oast": {"server": self.oast_server.get().strip() or "oast.pro", "mode": self.oast_mode.get(), "https": True},
                "plugin_timeout": 45}

    def _start_scan(self):
        cfg=self._collect_config()
        if not (cfg["target"] or cfg["targets"]):
            self.log_message("❗ Provide at least one target"); return
        if not (cfg["h1_api_key"] or cfg["bc_api_key"]):
            mbox.showinfo("API Key", "No API key found. You can add keys in Config. Scanning will still run.")
        self.start.configure(state="disabled", text="Scanning…")
        threading.Thread(target=lambda: asyncio.run(self._scan_bg(cfg)), daemon=True).start()

    async def _scan_bg(self, cfg):
        try:
            await run_scan(cfg, self.gui_queue)
        except Exception as e:
            self.gui_queue.put(("log", "FATAL: %s" % e))
        finally:
            self.gui_queue.put(("finished", None))

    def _process_queue(self):
        try:
            while True:
                typ, data = self.gui_queue.get_nowait()
                if typ=="log": self.log_message(data)
                elif typ=="finding":
                    iid=self.tree.insert("", "end", values=(data.severity, data.title)); self.findings_data[iid]=data
                elif typ=="finished":
                    self.start.configure(state="normal", text="Start Scan"); self.log_message("✅ Scan finished.")
        except queue.Empty: pass
        self.after(100, self._process_queue)

    def _show_evidence(self, _):
        sel=self.tree.focus()
        if sel in self.findings_data:
            f=self.findings_data[sel]
            txt="Description: %s\n\nEvidence: %s" % (getattr(f,'description',''), json.dumps(getattr(f,'evidence',{}), indent=2))
            self.evidence.delete("1.0","end"); self.evidence.insert("1.0", txt)

    def install_plugin(self):
        try:
            p = fd.askopenfilename(title="Select plugin (.py)", filetypes=[("Python","*.py")])
            if not p: return
            import shutil, os; os.makedirs("plugins", exist_ok=True)
            dst=os.path.join("plugins", os.path.basename(p))
            if os.path.abspath(p) == os.path.abspath(dst):
                self.log_message("ℹ️ Plugin already installed: %s" % dst)
                return
            shutil.copy(p, dst)
            self.log_message("✅ Installed plugin: %s" % dst)
            # Immediately refresh list to show it
            try:
                self._build_plugins_tab(self.tabs_left.tab("Plugins"))
            except Exception:
                pass
        except Exception as e:
            self.log_message("Install failed: %s" % e)

    def _all_findings_list(self): return [v for _,v in self.findings_data.items()]
    def export_all_html(self):
        from reporting import export_html; path = export_html(self._all_findings_list()); self.log_message("Exported HTML report: %s" % path)
    def export_all_docx(self):
        from reporting import export_docx; path = export_docx(self._all_findings_list()); self.log_message("Exported DOCX report: %s" % path)
    def export_all_pdf(self):
        from reporting import export_pdf; path = export_pdf(self._all_findings_list()); self.log_message("Exported PDF report: %s" % path)
    def export_selected_bug_pdf(self):
        sel=self.tree.focus()
        if sel not in self.findings_data:
            mbox.showinfo("Export", "Select a finding first from the Findings tab."); return
        finding=self.findings_data[sel]
        from reporting import export_bug_pdf; path = export_bug_pdf(finding, out_dir="reports", program_name="Program Profile")
        self.log_message("Exported Bug Bounty PDF: %s" % path)

    def run_self_test(self):
        self.selftest_out.delete("1.0","end")
        def worker():
            try:
                import diagnostics, io, sys
                buf=io.StringIO(); old_out=sys.stdout; sys.stdout=buf
                try:
                    diagnostics.check_imports(); diagnostics.check_engine(); diagnostics.check_plugins(); diagnostics.check_gui(); diagnostics.check_reporting()
                    print("\nDiagnostics completed.")
                finally:
                    sys.stdout=old_out
                self.selftest_out.insert("end", buf.getvalue())
            except Exception as e:
                self.selftest_out.insert("end", "Self-test failed: %s" % e)
        threading.Thread(target=worker, daemon=True).start()

    def on_close(self):
        try:
            os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
            yaml.safe_dump(self._collect_config(), open(CONFIG_FILE,"w",encoding="utf-8"), sort_keys=False)
        except Exception as e:
            self.log_message("Settings save failed: %s" % e)
        self.destroy()

if __name__ == "__main__":
    try:
        print("[DarkHunter] starting GUI…"); app=App(); app.mainloop()
    except Exception as e:
        import traceback; print("[DarkHunter] FATAL ERROR:", e); traceback.print_exc()
