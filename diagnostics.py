
"""
DarkHunter v7.7.0 – Diagnostics
"""
import importlib, os, sys, types
OK="✅"; FAIL="❌"; errs=[]
def check_imports():
    try:
        import customtkinter, tkinter, yaml, aiohttp, colorama
        print(OK, "Imports loaded")
    except Exception as e:
        errs.append(("imports", str(e))); print(FAIL, "Imports error:", e)
def check_engine():
    try:
        eng=importlib.import_module("engine")
        for fn in ["run_scan","request_stop"]: assert hasattr(eng, fn), f"engine missing {fn}"
        print(OK, "Engine OK")
    except Exception as e:
        errs.append(("engine", str(e))); print(FAIL, "Engine error:", e)
def check_plugins():
    try:
        mods=["plugins.check_headers","plugins.check_ssrf_oast","plugins.check_xss_reflected","plugins.check_graphql_detect"]
        for m in mods:
            mod=importlib.import_module(m); assert hasattr(mod,"Plugin"), f"{m} missing Plugin"; assert hasattr(mod,"CAPS"), f"{m} missing CAPS"
        print(OK, "Core plugins OK (CAPS present)")
    except Exception as e:
        errs.append(("plugins", str(e))); print(FAIL, "Plugins error:", e)
def check_gui():
    try:
        gui=importlib.import_module("gui")
        for fn in ["export_all_html","export_all_docx","export_all_pdf","run_self_test"]:
            assert fn in gui.App.__dict__, f"App missing {fn}"
        print(OK, "GUI exports & Self-Test bound")
    except Exception as e:
        errs.append(("gui", str(e))); print(FAIL, "GUI error:", e)
def check_reporting():
    try:
        rep=importlib.import_module("reporting")
        dummy=types.SimpleNamespace(severity="Info", title="Diag", description="Self test", evidence={"k":"v"})
        html=rep.export_html([dummy], out_dir="reports_diag", title="Diag HTML")
        docx=rep.export_docx([dummy], out_dir="reports_diag", title="Diag DOCX")
        pdf =rep.export_pdf ([dummy], out_dir="reports_diag", title="Diag PDF")
        bug =rep.export_bug_pdf(dummy, out_dir="reports_diag", program_name="DiagProg")
        for p in [html,docx,pdf,bug]:
            assert os.path.exists(p), f"missing {p}"
        print(OK, "Report exporters OK")
    except Exception as e:
        errs.append(("reporting", str(e))); print(FAIL, "Reporting error:", e)
if __name__=="__main__":
    os.chdir(os.path.dirname(__file__) or ".")
    check_imports(); check_engine(); check_plugins(); check_gui(); check_reporting()
    if errs:
        print("\n--- FAILURES ---"); 
        for k,v in errs: print("*", k, ":", v); sys.exit(1)
    print("\nAll diagnostics passed.")
