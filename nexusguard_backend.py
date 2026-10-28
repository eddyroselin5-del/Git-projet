import os
import sys
import time
import json
import socket
import struct
import ctypes
import threading
import subprocess
import datetime
from concurrent.futures import ThreadPoolExecutor

import psutil
import requests
import tkinter as tk
from tkinter import ttk, messagebox

# ==============================================================================
# CONFIGURATION & THEME UNIFIE (NEXUSGUARD / LASER)
# ==============================================================================
THEME = {
    "bg_main": "#07090e",
    "bg_panel": "#0b0f19",
    "bg_card": "#111827",
    "border": "#1f2937",
    "fg_primary": "#f3f4f6",
    "fg_secondary": "#9ca3af",
    "neon_cyan": "#06b6d4",
    "neon_green": "#10b981",
    "neon_red": "#ef4444",
    "neon_amber": "#f59e0b",
    "font_mono": ("Consolas", 9),
    "font_title": ("Inter", 16, "bold"),
    "font_subtitle": ("Inter", 10)
}

ip_cache = {}
blocked_apps_cache = set()


def is_admin():
    """Vérifie si le processus est exécuté avec les privilèges d'administrateur."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def format_size(num):
    """Formatage lisible des tailles de données (B, KB, MB, GB)."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if abs(num) < 1024.0:
            return f"{num:3.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"


def get_duration(create_time):
    """Calcule la durée d'exécution d'un processus."""
    try:
        delta = time.time() - create_time
        return str(datetime.timedelta(seconds=int(delta)))
    except Exception:
        return "00:00:00"


# ==============================================================================
# MOTEUR PARE-FEU SYSTÈME & INSPECTION DE SOCKETS
# ==============================================================================
class AdvancedSystemFirewall:
    @staticmethod
    def get_blocked_rules():
        """Récupère la liste des règles de filtrage actives dans Windows Firewall."""
        blocked = set()
        try:
            cmd = 'netsh advfirewall firewall show rule name=all verbose'
            output = subprocess.check_output(cmd, shell=True).decode('cp850', errors='ignore')

            current_rule = ""
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Rule Name:"):
                    current_rule = line.split(":", 1)[1].strip()
                if line.startswith("Program:") and "HF_BLOCK" in current_rule:
                    prog = line.split(":", 1)[1].strip()
                    if prog and prog != "Any":
                        blocked.add(prog.lower())
        except Exception:
            pass
        return blocked

    @staticmethod
    def block_executable(exe_path):
        """Ajoute des règles d'interdiction Entrée/Sortie pour un programme."""
        if not exe_path:
            return False
        rule_name = f"HF_BLOCK_{os.path.basename(exe_path)}"
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}" enable=yes'
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block program="{exe_path}" enable=yes'
        try:
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True,
                           stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(cmd_in, shell=True, check=True, stdout=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    @staticmethod
    def unblock_executable(exe_path):
        """Supprime la règle de blocage d'un programme."""
        if not exe_path:
            return False
        rule_name = f"HF_BLOCK_{os.path.basename(exe_path)}"
        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
            return True
        except Exception:
            return False


# ==============================================================================
# OUTILS DE DIAGNOSTIC RÉSEAU (PING & PORT SCANNER)
# ==============================================================================
class DiagnosticTools:
    @staticmethod
    def ping_target(host, count=4):
        """Exécute un test d'accessibilité ICMP / Ping."""
        results = []
        try:
            cmd = ["ping", "-n", str(count), host]
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for line in process.stdout:
                if line.strip():
                    results.append(line.strip())
        except Exception as e:
            results.append(f"Erreur de diagnostic: {e}")
        return results

    @staticmethod
    def scan_ports(host, ports=[21, 22, 80, 443, 3306, 8080, 8443]):
        """Analyse l'état d'ouverture d'une sélection de ports TCP."""
        results = []
        for port in ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            if result == 0:
                results.append((port, "OUVERT"))
            else:
                results.append((port, "FERMÉ"))
            s.close()
        return results


# ==============================================================================
# APPLICATION PRINCIPALE GRAPHIQUE (NEXUSGUARD PRO GUI)
# ==============================================================================
class NexusGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NexusGuard PRO - Centre de Contrôle Pare-feu")
        self.root.geometry("1380x850")
        self.root.configure(bg=THEME["bg_main"])

        self.executor = ThreadPoolExecutor(max_workers=12)
        self.all_data = []
        self.firewall_active = True
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_table)

        self.setup_styles()
        self.build_ui()

        # Démarrage de l'actualisation dynamique
        self.root.after(500, self.refresh_connections)
        self.root.after(3000, self.auto_refresh_loop)

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview",
                        background=THEME["bg_card"],
                        foreground=THEME["fg_primary"],
                        fieldbackground=THEME["bg_card"],
                        rowheight=32,
                        borderwidth=0,
                        font=THEME["font_mono"])
        style.configure("Treeview.Heading",
                        background=THEME["bg_panel"],
                        foreground=THEME["neon_cyan"],
                        font=("Segoe UI", 10, "bold"),
                        relief="flat")
        style.map("Treeview",
                  background=[('selected', THEME["border"])],
                  foreground=[('selected', THEME["neon_cyan"])])

    def build_ui(self):
        # --- EN-TÊTE PRINCIPAL ---
        header = tk.Frame(self.root, bg=THEME["bg_panel"], height=65, highlightbackground=THEME["border"],
                          highlightthickness=1)
        header.pack(fill="x", side="top")

        title_frame = tk.Frame(header, bg=THEME["bg_panel"])
        title_frame.pack(side="left", padx=20)
        tk.Label(title_frame, text="NEXUSGUARD", bg=THEME["bg_panel"], fg=THEME["fg_primary"],
                 font=THEME["font_title"]).pack(side="left")
        tk.Label(title_frame, text=" PRO", bg=THEME["bg_panel"], fg=THEME["neon_cyan"], font=THEME["font_title"]).pack(
            side="left")
        tk.Label(title_frame, text=" | FireWall Engine", bg=THEME["bg_panel"], fg=THEME["fg_secondary"],
                 font=THEME["font_subtitle"]).pack(side="left", padx=10)

        # Indicateur d'état du Pare-feu
        self.status_btn = tk.Button(header, text="PARE-FEU ACTIF", command=self.toggle_firewall_master,
                                    bg=THEME["neon_green"], fg="#000000", font=("Segoe UI", 9, "bold"),
                                    relief="flat", padx=15, pady=4)
        self.status_btn.pack(side="right", padx=20)

        # --- PANNEAU STATISTIQUES ---
        stats_frame = tk.Frame(self.root, bg=THEME["bg_main"])
        stats_frame.pack(fill="x", padx=20, pady=15)

        self.card_conn = self.create_stat_card(stats_frame, "CONNEXIONS ACTIVES", "0", THEME["neon_cyan"])
        self.card_blocked = self.create_stat_card(stats_frame, "PROGRAMMES BLOQUÉS", "0", THEME["neon_red"])
        self.card_bandwidth = self.create_stat_card(stats_frame, "DEBIT RÉSEAU", "0.0 MB/s", THEME["neon_amber"])

        # --- BARRE D'OUTILS ET RECHERCHE ---
        toolbar = tk.Frame(self.root, bg=THEME["bg_main"])
        toolbar.pack(fill="x", padx=20, pady=(0, 10))

        search_box = tk.Frame(toolbar, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1)
        search_box.pack(side="left", fill="x", expand=True, padx=(0, 15))

        tk.Label(search_box, text="  FILTRE : ", bg=THEME["bg_card"], fg=THEME["fg_secondary"],
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        entry = tk.Entry(search_box, textvariable=self.search_var, bg=THEME["bg_card"], fg="white",
                         insertbackground="white", relief="flat", font=("Segoe UI", 10))
        entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)

        tk.Button(toolbar, text="ACTUALISER", command=self.refresh_connections,
                  bg=THEME["neon_cyan"], fg="#000000", font=("Segoe UI", 9, "bold"), relief="flat", padx=15,
                  pady=6).pack(side="right")
        tk.Button(toolbar, text="OUTILS DIAGNOSTIC", command=self.open_diagnostic_modal,
                  bg=THEME["bg_card"], fg=THEME["neon_amber"], font=("Segoe UI", 9, "bold"), relief="flat", padx=15,
                  pady=6).pack(side="right", padx=10)

        # --- TABLEAU DE BORD (TREEVIEW) ---
        tree_container = tk.Frame(self.root, bg=THEME["bg_card"], highlightbackground=THEME["border"],
                                  highlightthickness=1)
        tree_container.pack(fill="both", expand=True, padx=20, pady=5)

        cols = ("PID", "PROCESSUS", "IP DISTANTE", "PORT", "ORGANISATION", "ÉMIS", "REÇU", "DURÉE", "CHEMIN")
        self.tree = ttk.Treeview(tree_container, columns=cols, show="headings", selectmode="browse")

        col_widths = [70, 180, 140, 70, 220, 100, 100, 100, 0]
        for col, w in zip(cols, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="center" if w < 150 else "w")
            if w == 0:
                self.tree.column(col, width=0, stretch=False)

        self.tree.tag_configure("safe", foreground=THEME["fg_primary"])
        self.tree.tag_configure("blocked", foreground=THEME["neon_red"])

        scrollbar = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        # --- PIED DE PAGE & ACTIONS ---
        footer = tk.Frame(self.root, bg=THEME["bg_panel"], height=60, highlightbackground=THEME["border"],
                          highlightthickness=1)
        footer.pack(fill="x", side="bottom")

        self.lbl_status = tk.Label(footer, text="Initialisation...", bg=THEME["bg_panel"], fg=THEME["fg_secondary"],
                                   font=THEME["font_mono"])
        self.lbl_status.pack(side="left", padx=20)

        btn_group = tk.Frame(footer, bg=THEME["bg_panel"])
        btn_group.pack(side="right", padx=20, pady=10)

        tk.Button(btn_group, text="BLOQUER PROGRAMME", command=self.block_app,
                  bg=THEME["neon_red"], fg="white", font=("Segoe UI", 9, "bold"), relief="flat", padx=15, pady=4).pack(
            side="left", padx=5)
        tk.Button(btn_group, text="DÉBLOQUER", command=self.unblock_app,
                  bg=THEME["neon_green"], fg="white", font=("Segoe UI", 9, "bold"), relief="flat", padx=15,
                  pady=4).pack(side="left", padx=5)
        tk.Button(btn_group, text="DÉTAILS", command=self.show_details,
                  bg=THEME["bg_card"], fg=THEME["neon_cyan"], font=("Segoe UI", 9, "bold"), relief="flat", padx=15,
                  pady=4).pack(side="left", padx=5)

    def create_stat_card(self, parent, title, val, color):
        card = tk.Frame(parent, bg=THEME["bg_card"], highlightbackground=THEME["border"], highlightthickness=1, padx=15,
                        pady=10)
        card.pack(side="left", fill="x", expand=True, padx=5)
        tk.Label(card, text=title, bg=THEME["bg_card"], fg=THEME["fg_secondary"], font=("Segoe UI", 8, "bold")).pack(
            anchor="w")
        lbl_val = tk.Label(card, text=val, bg=THEME["bg_card"], fg=color, font=("Consolas", 16, "bold"))
        lbl_val.pack(anchor="w", pady=(2, 0))
        return lbl_val

    def toggle_firewall_master(self):
        self.firewall_active = not self.firewall_active
        if self.firewall_active:
            self.status_btn.config(text="PARE-FEU ACTIF", bg=THEME["neon_green"], fg="#000000")
            self.lbl_status.config(text="Surveillance et filtrage en temps réel activés.")
        else:
            self.status_btn.config(text="PARE-FEU DÉSACTIVÉ", bg=THEME["neon_red"], fg="#ffffff")
            self.lbl_status.config(text="ATTENTION : Moteur de filtrage en pause.")

    def fetch_geo(self, ip, item_id):
        if ip in ip_cache:
            org = ip_cache[ip]
        else:
            if ip.startswith(('192.', '10.', '127.', '172.')):
                org = "Réseau Local / Intranet"
            else:
                try:
                    r = requests.get(f'http://ip-api.com/json/{ip}?fields=org', timeout=2)
                    org = r.json().get('org', 'Inconnu') if r.status_code == 200 else "Inconnu"
                except Exception:
                    org = "Erreur Lookup"
            ip_cache[ip] = org

        try:
            if self.tree.exists(item_id):
                vals = list(self.tree.item(item_id)['values'])
                vals[4] = org
                self.tree.item(item_id, values=vals)
        except Exception:
            pass

    def refresh_connections(self, is_auto=False):
        if not self.firewall_active and is_auto:
            return
        threading.Thread(target=self._scan_logic, args=(is_auto,), daemon=True).start()

    def auto_refresh_loop(self):
        self.refresh_connections(is_auto=True)
        self.root.after(3000, self.auto_refresh_loop)

    def _scan_logic(self, is_auto):
        global blocked_apps_cache
        if not is_auto:
            blocked_apps_cache = AdvancedSystemFirewall.get_blocked_rules()

        connections_count = 0
        total_bytes = 0
        existing_map = {}

        if is_auto:
            for iid, vals, tag in self.all_data:
                key = (vals[0], vals[2], vals[3])
                existing_map[key] = iid

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    pid = conn.pid
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe = proc.exe()

                        io = proc.io_counters()
                        sent = format_size(io.write_bytes)
                        recv = format_size(io.read_bytes)
                        total_bytes += (io.write_bytes + io.read_bytes)
                        duration = get_duration(proc.create_time())

                        tag = "blocked" if (exe and exe.lower() in blocked_apps_cache) else "safe"
                        vals = (pid, name, conn.raddr.ip, conn.raddr.port, "...", sent, recv, duration, exe)

                        self.root.after(0, self._sync_row, vals, tag, conn.raddr.ip, is_auto, existing_map)
                        connections_count += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
        except Exception as e:
            pass

        self.root.after(0, lambda: self._update_stats_ui(connections_count, len(blocked_apps_cache), total_bytes))

    def _sync_row(self, vals, tag, ip, is_auto, existing_map):
        key = (vals[0], vals[2], vals[3])
        found_id = existing_map.get(key)

        if is_auto and found_id:
            current_org = self.tree.item(found_id)['values'][4]
            new_vals = list(vals)
            new_vals[4] = current_org
            self.tree.item(found_id, values=new_vals, tags=(tag,))
        elif not is_auto or not found_id:
            item_id = self.tree.insert("", "end", values=vals, tags=(tag,))
            self.all_data.append((item_id, vals, tag))
            self.executor.submit(self.fetch_geo, ip, item_id)
            self.filter_table()

    def _update_stats_ui(self, conn_count, blocked_count, total_bytes):
        self.card_conn.config(text=str(conn_count))
        self.card_blocked.config(text=str(blocked_count))
        self.card_bandwidth.config(text=format_size(total_bytes) + "/s")
        self.lbl_status.config(
            text=f"Moteur Actif - {conn_count} flux inspectés | Mise à jour: {datetime.datetime.now().strftime('%H:%M:%S')}")

    def filter_table(self, *args):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        for iid, vals, tag in self.all_data:
            content = f"{vals[0]} {vals[1]} {vals[2]} {vals[4]}".lower()
            if query in content:
                self.tree.insert("", "end", iid=iid, values=vals, tags=(tag,))

    def block_app(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])['values']
        path, name = vals[8], vals[1]

        if messagebox.askyesno("Blocage Pare-feu", f"Bloquer tout le trafic réseau pour {name} ?"):
            if AdvancedSystemFirewall.block_executable(path):
                messagebox.showinfo("Succès", f"{name} a été bloqué avec succès.")
                self.refresh_connections()
            else:
                messagebox.showerror("Erreur", "Droits d'administration requis.")

    def unblock_app(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])['values']
        path = vals[8]

        if messagebox.askyesno("Déblocage", f"Autoriser de nouveau le trafic pour {vals[1]} ?"):
            if AdvancedSystemFirewall.unblock_executable(path):
                messagebox.showinfo("Succès", "Règle de filtrage supprimée.")
                self.refresh_connections()

    def show_details(self):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0])['values']

        win = tk.Toplevel(self.root)
        win.title(f"Inspecteur de Flux : {vals[1]}")
        win.geometry("520x460")
        win.configure(bg=THEME["bg_card"])

        tk.Label(win, text=f"PROCESSUS: {vals[1]}", bg=THEME["bg_card"], fg=THEME["neon_cyan"],
                 font=THEME["font_title"]).pack(pady=15)

        info_frame = tk.Frame(win, bg=THEME["bg_card"], padx=20)
        info_frame.pack(fill="both", expand=True)

        details = [
            ("ID Processus (PID)", vals[0]),
            ("Chemin d'accès", vals[8]),
            ("Adresse IP Distante", vals[2]),
            ("Port Distant", vals[3]),
            ("Fournisseur / Org", vals[4]),
            ("Données Émises", vals[5]),
            ("Données Reçues", vals[6]),
            ("Temps d'Exécution", vals[7])
        ]

        for label, val in details:
            r = tk.Frame(info_frame, bg=THEME["bg_card"], pady=4)
            r.pack(fill="x")
            tk.Label(r, text=label + ":", width=20, anchor="w", bg=THEME["bg_card"], fg=THEME["fg_secondary"],
                     font=("Segoe UI", 9)).pack(side="left")
            tk.Label(r, text=str(val), bg=THEME["bg_card"], fg="white", font=THEME["font_mono"], wraplength=300,
                     justify="left").pack(side="left")

        tk.Button(win, text="FERMER", command=win.destroy, bg=THEME["neon_cyan"], fg="black",
                  font=("Segoe UI", 9, "bold")).pack(pady=15)

    def open_diagnostic_modal(self):
        diag_win = tk.Toplevel(self.root)
        diag_win.title("Outils de Diagnostic Réseau ICMP / TCP")
        diag_win.geometry("600x500")
        diag_win.configure(bg=THEME["bg_card"])

        tk.Label(diag_win, text="DIAGNOSTIC ET SCANNER DE PORTS", bg=THEME["bg_card"], fg=THEME["neon_amber"],
                 font=THEME["font_title"]).pack(pady=10)

        input_frame = tk.Frame(diag_win, bg=THEME["bg_card"])
        input_frame.pack(fill="x", padx=20, pady=5)

        tk.Label(input_frame, text="Hôte / IP : ", bg=THEME["bg_card"], fg="white").pack(side="left")
        target_entry = tk.Entry(input_frame, bg=THEME["bg_main"], fg="white", font=THEME["font_mono"])
        target_entry.insert(0, "1.1.1.1")
        target_entry.pack(side="left", fill="x", expand=True, padx=10)

        output_text = tk.Text(diag_win, bg=THEME["bg_main"], fg=THEME["neon_green"], font=THEME["font_mono"], height=18)
        output_text.pack(fill="both", expand=True, padx=20, pady=10)

        def run_ping():
            output_text.delete('1.0', tk.END)
            target = target_entry.get()
            output_text.insert(tk.END, f"--- Exécution de Ping vers {target} ---\n")
            lines = DiagnosticTools.ping_target(target)
            for line in lines:
                output_text.insert(tk.END, line + "\n")

        def run_scan():
            output_text.delete('1.0', tk.END)
            target = target_entry.get()
            output_text.insert(tk.END, f"--- Analyse des ports TCP standard sur {target} ---\n")
            results = DiagnosticTools.scan_ports(target)
            for port, status in results:
                output_text.insert(tk.END, f"Port {port}/TCP : {status}\n")

        btn_box = tk.Frame(diag_win, bg=THEME["bg_card"])
        btn_box.pack(fill="x", padx=20, pady=10)
        tk.Button(btn_box, text="LANCER PING", command=lambda: threading.Thread(target=run_ping).start(),
                  bg=THEME["neon_cyan"], fg="black", font=("Segoe UI", 9, "bold")).pack(side="left", padx=5)
        tk.Button(btn_box, text="SCANNER PORTS", command=lambda: threading.Thread(target=run_scan).start(),
                  bg=THEME["neon_amber"], fg="black", font=("Segoe UI", 9, "bold")).pack(side="left", padx=5)


# ==============================================================================
# POINT D'ENTRÉE DU PROGRAMME
# ==============================================================================
if __name__ == "__main__":
    if not is_admin():
        try:
            if len(sys.argv) == 1 or sys.argv[-1] != "as_admin":
                params = " ".join([f'"{a}"' for a in sys.argv] + ["as_admin"])
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                sys.exit()
        except Exception as e:
            sys.exit()

    root = tk.Tk()
    app = NexusGuardApp(root)
    root.mainloop()