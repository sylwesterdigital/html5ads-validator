from __future__ import annotations
import io, re, zipfile, tempfile, shutil, time, base64, pathlib
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import List, Dict, Any
from bs4 import BeautifulSoup
import cssutils, brotli

try:
    from playwright.sync_api import sync_playwright
    HAVE_PW = True
except Exception:
    HAVE_PW = False

try:
    from PIL import Image
    HAVE_PIL = True
except Exception:
    HAVE_PIL = False


@dataclass
class Check:
    id: str
    category: str   # Archive|Policy|Runtime|Network
    label: str
    status: str     # green|yellow|red|gray
    value: str
    help: str = ""


def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    f = float(n)
    for u in units:
        if f < 1024 or u == "GB":
            return f"{f:.1f} {u}" if u != "B" else f"{int(f)} {u}"
        f /= 1024
    return f"{f:.1f} GB"


def make_scan_metadata(user_agent: str, original_name: str) -> Dict[str, Any]:
    return {
        "scan_type": "Local Web scan",
        "api_version": "v1",
        "hardware": "Local",
        "unix_timestamp": int(time.time()),
        "scan_duration": None,
        "creative_type": "HTML5 Zip",
        "original_name": original_name,
        "device": "Desktop",
        "language": "en-US",
        "user_agent": user_agent,
    }


class Validator:
    def __init__(self, cfg: Dict[str, Any], logger=None):
        self.cfg = cfg
        self.log = logger
        self.have_playwright = HAVE_PW
        self.click_res = [re.compile(p, re.I) for p in cfg.get("click_patterns", [])]
        self.http_re = re.compile(r"https?://[^\s'\"()<>]+", re.I)
        self.cookie_re = re.compile(r"document\.cookie\s*=")
        self.doc_write_re = re.compile(r"document\.write\s*\(", re.I)

    # --------- Main ----------
    def analyze(self, bytes_io: io.BytesIO, original_name: str, run_dir: Path) -> Dict[str, Any]:
        t0 = time.time()
        try:
            zf = zipfile.ZipFile(bytes_io)
        except Exception as e:
            return {"error": f"Invalid ZIP: {e}"}

        entries = zf.infolist()
        names = [e.filename for e in entries]
        archive_listing, checks = [], []

        # Persist raw zip
        (run_dir / "unzipped").mkdir(parents=True, exist_ok=True)
        zf.extractall(run_dir / "unzipped")

        # Archive listing
        for e in entries:
            archive_listing.append({
                "name": e.filename, "is_dir": e.is_dir(),
                "size": e.file_size, "compressed": e.compress_size,
            })

        # Compressed size
        size_bytes = bytes_io.getbuffer().nbytes
        max_bytes = int(self.cfg.get("max_zip_bytes", 204800))
        checks.append(Check("compressed_file_size","Archive","Compressed File Size",
                            "green" if size_bytes <= max_bytes else "red",
                            human_bytes(size_bytes), f"Limit {human_bytes(max_bytes)}"))

        # Brotli size
        total_text, total_br = 0, 0
        for e in entries:
            if e.is_dir(): continue
            ext = Path(e.filename).suffix.lower()
            if ext in {".html",".htm",".css",".js"}:
                buf = zf.read(e)
                total_text += len(buf)
                total_br += len(brotli.compress(buf))
        checks.append(Check("brotli_text_size","Archive","Text Brotli Size",
                            "green" if total_text else "gray",
                            human_bytes(total_br) if total_text else "—",
                            f"Raw {human_bytes(total_text)}" if total_text else "No HTML/CSS/JS"))

        # Junk
        junk_prefixes = tuple(self.cfg.get("junk_prefixes", []))
        junk_files = set(self.cfg.get("junk_files", []))
        junk_found = [n for n in names if n.startswith(junk_prefixes) or Path(n).name in junk_files]
        checks.append(Check("junk_files","Archive","Junk Files",
                            "red" if junk_found else "green",
                            "Yes" if junk_found else "No",
                            ", ".join(junk_found[:8])))

        # root index
        has_index_root = any(n == "index.html" for n in names)
        require_index = bool(self.cfg.get("require_root_index", True))
        checks.append(Check("index_html","Archive","Root index.html",
                            "green" if (has_index_root or not require_index) else "red",
                            "Yes" if has_index_root else "No"))

        # types
        allow_ext = set(map(str.lower, self.cfg.get("allow_ext", [])))
        deny_ext = set(map(str.lower, self.cfg.get("deny_ext", [])))
        denied = [n for n in names if Path(n).suffix.lower() in deny_ext]
        unlisted = [n for n in names if Path(n).suffix and Path(n).suffix.lower() not in allow_ext | deny_ext]
        checks.append(Check("denied_ext","Archive","Blocked File Types",
                            "red" if denied else "green", "Present" if denied else "None",
                            ", ".join(denied[:8])))
        checks.append(Check("unlisted_ext","Archive","Unlisted Extensions",
                            "yellow" if unlisted else "green",
                            str(len(unlisted)), ", ".join(unlisted[:8])))

        # images dimension
        img_list = [n for n in names if Path(n).suffix.lower() in {".png",".jpg",".jpeg",".gif",".webp",".svg"}]
        oversized = []
        if HAVE_PIL:
            for n in img_list:
                if n.lower().endswith(".svg"): continue
                try:
                    with zf.open(n) as f:
                        im = Image.open(io.BytesIO(f.read()))
                        w, h = im.size
                        if max(w,h) > 2048: oversized.append(f"{n} ({w}x{h})")
                except Exception:
                    pass
        checks.append(Check("image_dimensions","Archive","Image Dimensions",
                            "yellow" if oversized else "green",
                            "Oversized" if oversized else "OK",
                            "; ".join(oversized[:6])))

        # text scrape
        html_js_texts = []
        for n in names:
            if Path(n).suffix.lower() in {".html",".htm",".js"} and not n.endswith("/"):
                try: html_js_texts.append(zf.read(n).decode("utf-8", errors="ignore"))
                except: pass
        all_text = "\n".join(html_js_texts)

        # backup ad heuristic
        has_backup = any(re.search(r"/(?:backup|fallback)\.(?:jpg|jpeg|png|gif)$", n, re.I) or
                         re.search(r"^(?:backup|fallback)\.(?:jpg|jpeg|png|gif)$", Path(n).name, re.I)
                         for n in names)
        checks.append(Check("has_backup_ad","Policy","Backup Ad","green" if has_backup else "red",
                            "Yes" if has_backup else "No"))

        # clickTag
        has_click = any(rx.search(all_text) for rx in self.click_res) if self.click_res else False
        checks.append(Check("click_through","Policy","Click Through",
                            "green" if has_click else "red",
                            "clickTag/Enabler" if has_click else "None"))

        # external urls
        allow_remote = bool(self.cfg.get("allow_remote_urls", False))
        externals = sorted(set(self.http_re.findall(all_text))) if not allow_remote else []
        checks.append(Check("external_urls","Network","External URLs",
                            "red" if externals else ("gray" if allow_remote else "green"),
                            str(len(externals)) if externals else ("—" if allow_remote else "0"),
                            " ".join(externals[:2])))

        # policy bits
        cookie_set = bool(self.cookie_re.search(all_text))
        doc_write = bool(self.doc_write_re.search(all_text))
        checks.append(Check("cookies_dropped","Policy","Cookies Dropped",
                            "red" if cookie_set else "green", "Yes" if cookie_set else "0"))
        checks.append(Check("document_write","Policy","Uses document.write()",
                            "red" if doc_write else "green", "Yes" if doc_write else "No"))

        # css/minified
        css_embedded = any("<style" in t.lower() or " style=" in t.lower() for t in html_js_texts)
        checks.append(Check("css_embedded","Policy","CSS Embedded","green" if css_embedded else "yellow",
                            "Yes" if css_embedded else "No"))

        def sniff_minified(s: str) -> bool:
            if not s: return False
            lines = s.splitlines() or [s]
            avg_len = sum(len(l) for l in lines)/max(1,len(lines))
            ws = sum(c.isspace() for c in s) / max(1,len(s))
            return avg_len > 80 and ws < 0.25

        min_css = any(sniff_minified((run_dir/"unzipped"/n).read_text("utf-8",errors="ignore"))
                      for n in names if n.lower().endswith(".css") and (run_dir/"unzipped"/n).exists())
        min_js  = any(sniff_minified((run_dir/"unzipped"/n).read_text("utf-8",errors="ignore"))
                      for n in names if n.lower().endswith(".js") and (run_dir/"unzipped"/n).exists())
        checks.append(Check("minified_css_js","Policy","CSS/JS Minified",
                            "green" if (min_css or min_js) else "yellow",
                            ", ".join([p for p,ok in (("CSS",min_css),("JS",min_js)) if ok]) or "No"))

        # runtime via Playwright
        runtime, thumbs = {}, []
        entry_url = f"/runs/PLACEHOLDER/file/index.html"  # finalised below

        dims = {"width": 0, "height": 0}
        if HAVE_PW and has_index_root:
            idx = (run_dir / "unzipped" / "index.html")
            dcl, err_ct, warn_ct, anim_ms, net_rows, dims, tti_ms, cpu_ms, heap_kb, thumbs = self._render_metrics(idx, run_dir)
            runtime = {
                "dom_content_loaded_ms": dcl,
                "time_to_visual_start_ms": tti_ms,
                "console_errors": err_ct,
                "console_warnings": warn_ct,
                "animation_duration_ms": anim_ms,
                "dimensions": dims,
                "network_requests": net_rows,
                "cpu_busy_ms_5s": cpu_ms,
                "js_heap_kb": heap_kb,
            }
            good_dcl = int(self.cfg.get("dcl_ms_good", 1000))
            anim_max = int(self.cfg.get("animation_max_ms", 15000))
            checks.extend([
                Check("dom_content_loaded","Runtime","DOMContentLoaded",
                      "green" if dcl < good_dcl else "yellow", f"{dcl} ms", f"< {good_dcl} ms ideal"),
                Check("time_to_visual","Runtime","Time to Visual Start",
                      "green" if tti_ms is not None and tti_ms < 1500 else "yellow",
                      f"{tti_ms} ms" if tti_ms is not None else "—"),
                Check("js_errors","Runtime","Console Errors","green" if err_ct==0 else "red", str(err_ct)),
                Check("console_warnings","Runtime","Console Warnings","green" if warn_ct==0 else "gray", str(warn_ct)),
                Check("animation_duration","Runtime","Animation Duration",
                      "green" if (anim_ms!=-1 and anim_ms<=anim_max) else "yellow",
                      "infinite" if anim_ms==-1 else f"{anim_ms} ms",
                      f"≤ {anim_max} ms ideal"),
                Check("dimensions","Runtime","Dimensions","green", f"{dims['width']}x{dims['height']}"),
                Check("hosted_file_count","Network","Hosted File Count","green", str(len(net_rows))),
                Check("hosted_file_size","Network","Hosted File Size","green",
                      human_bytes(sum(int(r.get('bytes',0) or 0) for r in net_rows if r.get('bytes')))),
                Check("ssl_compat","Network","SSL-Compatibility",
                      "green" if all((r.get('url','').startswith('https://')) for r in net_rows) else "yellow",
                      "Yes" if all((r.get('url','').startswith('https://')) for r in net_rows) else "Mixed"),
            ])

        # final URL for iframe viewer
        entry_url = f"/runs/{{run_id}}/file/index.html"

        elapsed = time.time() - t0
        results = [asdict(c) for c in checks]
        return {
            "results": results,
            "archive": archive_listing,
            "runtime": runtime,
            "thumbnails": thumbs,
            "metadata": {"scan_duration": round(elapsed, 2)},
            "entry_url": entry_url,  # {run_id} placeholder; app fills it in response
        }

    # ---- Playwright probe & thumbnails ----
    def _render_metrics(self, index_path: Path, run_dir: Path):
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            page = browser.new_page()
            err_ct = warn_ct = 0
            net_rows = []

            page.on("console", lambda m: (m.type=="error" and (globals().__setitem__('x', None), [])[1]))
            def on_console(msg):
                nonlocal err_ct, warn_ct
                if msg.type == "error": err_ct += 1
                elif msg.type == "warning": warn_ct += 1
            page.on("console", on_console)

            def on_request_finished(req):
                try:
                    resp = req.response()
                    length = None
                    if resp:
                        length = resp.headers.get("content-length")
                        if not length:
                            try:
                                body = resp.body()
                                length = len(body)
                            except Exception:
                                length = None
                    net_rows.append({
                        "url": req.url,
                        "status": (resp.status if resp else None),
                        "protocol": (resp.request.timing.get("protocol") if resp and resp.request.timing else None),
                        "enc": (resp.headers.get("content-encoding") if resp else None),
                        "bytes": int(length) if length else None,
                        "type": (resp.headers.get("content-type") if resp else None),
                    })
                except Exception:
                    pass
            page.on("requestfinished", on_request_finished)

            t0 = time.time()
            page.goto(index_path.as_uri(), wait_until="domcontentloaded")
            dcl = int((time.time() - t0) * 1000)

            dims = page.evaluate("""
                () => {
                  const el = document.body;
                  const r = el.getBoundingClientRect();
                  return { width: Math.round(r.width||300), height: Math.round(r.height||250) };
                }
            """)

            tti = page.evaluate("""
                () => {
                  const nav = performance.getEntriesByType('navigation')[0];
                  if (nav && nav.responseEnd) return Math.round(nav.responseEnd);
                  return null;
                }
            """)

            max_anim_ms = page.evaluate("""
                () => {
                  function dur(s){ if(!s) return 0;
                    return Math.max(...s.split(',').map(x=>x.trim()).map(v=>v.endsWith('ms')?parseFloat(v):v.endsWith('s')?parseFloat(v)*1000:0));}
                  function iter(s){ if(!s) return 1;
                    const arr=s.split(',').map(x=>x.trim());
                    for(const v of arr){ if(v==='infinite') return -1; }
                    return Math.max(...arr.map(v=>parseFloat(v)||1)); }
                  let maxT=0; for(const el of document.querySelectorAll('*')){
                    const cs=getComputedStyle(el); const d=dur(cs.animationDuration); const it=iter(cs.animationIterationCount);
                    if(it===-1) return -1; const tot=d*it; if(tot>maxT) maxT=tot;
                  } return Math.round(maxT);
                }
            """)

            cpu_ms = page.evaluate("""
                async () => {
                  const start = performance.now(); let busy=0, last=start;
                  while(performance.now()-start<5000){
                    const t=performance.now(); const dt=t-last; last=t;
                    if(dt>16.7) busy += (dt-16.7);
                    await new Promise(r=>requestAnimationFrame(()=>r()));
                  }
                  return Math.round(busy);
                }
            """)
            heap_kb = page.evaluate("() => Math.round((performance.memory && performance.memory.usedJSHeapSize || 0)/1024)")

            # thumbnails + downloadable backups
            times_sec = [1.4, 3.4, 5.4, 7.4, 9.4, 11.4]
            page.set_viewport_size({"width": max(1,int(dims['width'])), "height": max(1,int(dims['height']))})
            t_start = time.time()
            thumbs = []
            for t_s in times_sec:
                wait_ms = max(0, int(t_s*1000 - (time.time() - t_start)*1000))
                if wait_ms: page.wait_for_timeout(wait_ms)
                png = page.screenshot(full_page=False)
                # save high-res PNG so user can download as "backup ad"
                out = run_dir / f"backup_{str(t_s).replace('.','_')}.png"
                out.write_bytes(png)
                thumbs.append({"t_sec": t_s, "png_b64": "data:image/png;base64,"+base64.b64encode(png).decode("ascii")})

            browser.close()
            return dcl, err_ct, warn_ct, max_anim_ms, net_rows, dims, tti, cpu_ms, heap_kb, thumbs
