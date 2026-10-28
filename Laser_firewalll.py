import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import subprocess
import threading
import requests
import ctypes
import sys
import os
import time
import datetime
from concurrent.futures import ThreadPoolExecutor

# --- CONFIGURATION DU DESIGN ---
THEME = {
    "bg_main": "#0b0f19",  # Fond principal sombre
    "bg_panel": "#161b22",  # Fond des panneaux/conteneurs
    "fg_primary": "#e6edf3",  # Texte principal (Blanc cassé)
    "fg_secondary": "#8b949e",  # Texte secondaire (Gris)
    "accent": "#00dbff",  # Cyan (Titres, Bordures)
    "danger": "#da3633",  # Rouge (Bouton Bloquer)
    "success": "#238636",  # Vert (Bouton Débloquer)
    "font_mono": ("Consolas", 10),
    "font_title": ("Segoe UI", 20, "bold")  # Taille augmentée pour l'impact
}

# Cache et listes
ip_cache = {}
blocked_apps_cache = set()


# --- FONCTIONS UTILITAIRES ---

def is_admin():
    """Vérifie les droits d'admin"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def get_size_fmt(num):
    """Convertit les octets en format lisible (Mo, Go)"""
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti']:
        if abs(num) < 1024.0:
            return "%3.1f %sB" % (num, unit)
        num /= 1024.0
    return "%.1f %sB" % (num, 'Pi')


def get_duration_fmt(create_time):
    """Calcule la durée d'exécution du processus"""
    try:
        delta = time.time() - create_time
        return str(datetime.timedelta(seconds=int(delta)))
    except:
        return "00:00:00"


# --- MOTEUR PARE-FEU ---

class SystemFirewall:
    @staticmethod
    def get_blocked_apps():
        """Récupère les chemins d'exécutables bloqués par nos règles (HF_BLOCK)"""
        blocked = set()
        try:
            cmd = 'netsh advfirewall firewall show rule name=all verbose'
            output = subprocess.check_output(cmd, shell=True).decode('cp850', errors='ignore')

            current_rule = ""
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Rule Name:"):
                    current_rule = line.split(":", 1)[1].strip()
                if line.startswith("Program:") and "HF_BLOCK" in current_rule and (
                        "action=block" in current_rule.lower() or "action=block" in line.lower()):
                    prog = line.split(":", 1)[1].strip()
                    if prog and prog != "Any":
                        blocked.add(prog.lower())
        except Exception:
            pass
        return blocked

    @staticmethod
    def block_executable(exe_path):
        if not exe_path: return False
        rule_name = f"HF_BLOCK_{os.path.basename(exe_path)}"
        cmd_out = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{exe_path}" enable=yes'
        cmd_in = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block program="{exe_path}" enable=yes'
        try:
            subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name}"', shell=True,
                           stderr=subprocess.DEVNULL)
            subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(cmd_in, shell=True, stdout=subprocess.DEVNULL)
            return True
        except:
            return False

    @staticmethod
    def unblock_executable(exe_path):
        if not exe_path: return False
        rule_name = f"HF_BLOCK_{os.path.basename(exe_path)}"
        try:
            cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
            return True
        except:
            return False


# --- INTERFACE GRAPHIQUE ---

class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡️ L.A.S.E.R | Firewall")
        self.root.geometry("1300x800")
        self.root.configure(bg=THEME["bg_main"])

        self.executor = ThreadPoolExecutor(max_workers=10)
        self.all_data = []
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_table)

        self.configure_styles()
        self.create_interface()

        self.root.after(500, self.refresh_connections)
        # Déclenchement du rafraîchissement auto toutes les 3 secondes
        self.root.after(3000, self.auto_refresh)

    def auto_refresh(self):
        """Appel au rafraîchissement toutes les 3 secondes pour le 'temps réel'."""
        self.refresh_connections(is_auto=True)
        self.root.after(3000, self.auto_refresh)

    def configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # Style uniforme pour toutes les lignes (retrait du Rouge/Vert)
        style.configure("Treeview",
                        background=THEME["bg_panel"],
                        foreground=THEME["fg_primary"],  # Couleur uniforme
                        fieldbackground=THEME["bg_panel"],
                        rowheight=35,
                        borderwidth=0,
                        font=THEME["font_mono"])

        style.configure("Treeview.Heading",
                        background=THEME["bg_main"],
                        foreground=THEME["accent"],
                        font=("Segoe UI", 11, "bold"),
                        relief="flat")

        style.map("Treeview", background=[('selected', THEME["accent"])], foreground=[('selected', 'black')])

    def create_interface(self):
        # --- EN-TÊTE ---
        header = tk.Frame(self.root, bg=THEME["bg_main"], height=80)
        header.pack(fill="x", padx=25, pady=20)

        # Titre de l'application
        tk.Label(header, text="L.A.S.E.R | Firewall", bg=THEME["bg_main"], fg=THEME["accent"],
                 font=THEME["font_title"]).pack(side="left")



        # --- BARRE D'OUTILS ---
        toolbar = tk.Frame(self.root, bg=THEME["bg_main"])
        toolbar.pack(fill="x", padx=25, pady=(0, 15))

        search_frame = tk.Frame(toolbar, bg=THEME["bg_panel"], padx=10, pady=5)
        search_frame.pack(side="left", fill="x", expand=True, padx=(0, 20))

        tk.Label(search_frame, text=" FILTRE / RECHERCHE :", bg=THEME["bg_panel"], fg=THEME["fg_secondary"]).pack(
            side="left")
        entry = tk.Entry(search_frame, textvariable=self.search_var, bg=THEME["bg_main"], fg="white",
                         insertbackground="white", relief="flat", font=("Segoe UI", 11))
        entry.pack(side="left", fill="x", expand=True, padx=10)

        # Bouton Refresh
        self.btn_refresh = tk.Button(toolbar, text=" ACTUALISER", command=self.refresh_connections,
                                     bg=THEME["accent"], fg="black", relief="flat", font=("Segoe UI", 10, "bold"),
                                     padx=20, pady=5)
        self.btn_refresh.pack(side="right")

        # --- TABLEAU ---
        tree_container = tk.Frame(self.root, bg=THEME["bg_panel"])
        tree_container.pack(fill="both", expand=True, padx=25)

        # Colonnes ajustéespip
        cols = ("PID", "PROCESSUS", "IP DISTANTE", "PORT", "ORGANISATION", "ENVOYÉ", "REÇU", "DURÉE", "CHEMIN")
        self.tree = ttk.Treeview(tree_container, columns=cols, show="headings", selectmode="browse")

        col_widths = [60, 180, 130, 60, 200, 90, 90, 90, 0]

        for col, w in zip(cols, col_widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=w, anchor="center" if w < 150 else "w")
            if w == 0: self.tree.column(col, width=0, stretch=False)

            # Les tags existent pour l'état, mais sans couleur spécifique
        self.tree.tag_configure("safe", foreground=THEME["fg_primary"])
        self.tree.tag_configure("blocked", foreground=THEME["fg_primary"])

        sb = ttk.Scrollbar(tree_container, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        # --- PIED DE PAGE (FOOTER) ---
        footer = tk.Frame(self.root, bg=THEME["bg_main"], height=100)
        footer.pack(fill="x", padx=25, pady=25)

        self.lbl_status = tk.Label(footer, text="Prêt.", bg=THEME["bg_main"], fg=THEME["fg_secondary"],
                                   font=("Consolas", 10))
        self.lbl_status.pack(side="top", anchor="w", pady=(0, 10))

        btn_frame = tk.Frame(footer, bg=THEME["bg_main"])
        btn_frame.pack(side="left", fill="x")

        tk.Button(btn_frame, text=" BLOQUER L'ACCÈS", command=self.block_app, bg=THEME["danger"], fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=8).pack(side="left", padx=(0, 10))

        tk.Button(btn_frame, text=" DÉBLOQUER", command=self.unblock_app, bg=THEME["success"], fg="white",
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=8).pack(side="left", padx=(0, 10))

        tk.Button(btn_frame, text=" DÉTAILS COMPLETS", command=self.show_details, bg=THEME["bg_panel"],
                  fg=THEME["accent"],
                  font=("Segoe UI", 10, "bold"), relief="flat", padx=20, pady=8).pack(side="left", padx=(0, 10))

    # --- LOGIQUE DE SCAN ---

    def fetch_geo(self, ip, item_id):
        """Récupère l'organisation IP en arrière-plan"""
        if ip in ip_cache:
            data = ip_cache[ip]
        else:
            if ip.startswith(('192.', '10.', '127.', '172.')):
                data = ("Réseau Local")
            else:
                try:
                    r = requests.get(f'http://ip-api.com/json/{ip}?fields=org', timeout=2)
                    if r.status_code == 200:
                        j = r.json()
                        data = (j.get('org', '?'))
                    else:
                        data = ("?")
                except:
                    data = ("Erreur")
            ip_cache[ip] = data

        try:
            if self.tree.exists(item_id):
                vals = list(self.tree.item(item_id)['values'])
                vals[4] = data
                self.tree.item(item_id, values=vals)

                for i, row in enumerate(self.all_data):
                    if row[0] == item_id:
                        new_vals = list(row[1])
                        new_vals[4] = data
                        self.all_data[i] = (item_id, new_vals, row[2])
        except:
            pass

    def refresh_connections(self, is_auto=False):
        """Lance le scan."""
        if not is_auto:
            self.btn_refresh.config(state="disabled", text="SCAN EN COURS...")
            self.lbl_status.config(text="Analyse des processus et du trafic réseau...")
            self.tree.delete(*self.tree.get_children())
            self.all_data = []

        threading.Thread(target=self._scan_logic, args=(is_auto,), daemon=True).start()

    def _scan_logic(self, is_auto):
        global blocked_apps_cache
        if not is_auto:
            blocked_apps_cache = SystemFirewall.get_blocked_apps()

        count = 0

        # Dictionnaire pour stocker les connexions existantes (pour la mise à jour auto)
        existing_conn = {}
        if is_auto:
            for iid, vals, tag in self.all_data:
                # Clé unique: PID + IP_DISTANTE + PORT
                key = (vals[0], vals[2], vals[3])
                existing_conn[key] = iid

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    pid = conn.pid
                    try:
                        proc = psutil.Process(pid)
                        name = proc.name()
                        exe = proc.exe()

                        io = proc.io_counters()
                        sent = get_size_fmt(io.write_bytes)
                        recv = get_size_fmt(io.read_bytes)
                        duration = get_duration_fmt(proc.create_time())

                        tag = "safe"
                        if exe and exe.lower() in blocked_apps_cache:
                            tag = "blocked"

                        r_ip = conn.raddr.ip
                        r_port = conn.raddr.port

                        # (0:PID, 1:Name, 2:IP, 3:Port, 4:Org, 5:Sent, 6:Recv, 7:Dur, 8:Path)
                        vals = (pid, name, r_ip, r_port, "...", sent, recv, duration, exe)

                        self.root.after(0, self._update_or_insert_row, vals, tag, r_ip, is_auto, existing_conn)
                        count += 1

                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

        except Exception as e:
            print(f"Erreur Scan: {e}")

        if not is_auto:
            self.root.after(0, lambda: self._finish_scan(count))

    def _update_or_insert_row(self, vals, tag, ip, is_auto, existing_conn):
        pid, r_ip, r_port = vals[0], vals[2], vals[3]
        key = (pid, r_ip, r_port)
        found_id = existing_conn.get(key)

        if is_auto and found_id:
            # Mise à jour des stats IO et Durée
            new_vals = list(vals)
            # Garder l'Organisation car la recherche Géo est asynchrone
            current_org = self.tree.item(found_id)['values'][4]
            new_vals[4] = current_org

            # Mise à jour du Treeview
            self.tree.item(found_id, values=new_vals, tags=(tag,))

            # Mise à jour du cache local
            for i, row in enumerate(self.all_data):
                if row[0] == found_id:
                    self.all_data[i] = (found_id, new_vals, tag)

        elif not is_auto or not found_id:
            # Insertion initiale ou nouvelle connexion
            item_id = self.tree.insert("", "end", values=vals, tags=(tag,))
            self.all_data.append((item_id, vals, tag))
            self.executor.submit(self.fetch_geo, ip, item_id)
            self.filter_table()

    def _finish_scan(self, count):
        self.btn_refresh.config(state="normal", text=" ACTUALISER")
        self.lbl_status.config(
            text=f"Scan terminé : {count} connexions actives. Rafraîchissement auto dans 3 secondes.")

    def filter_table(self, *args):
        query = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())

        for iid, vals, tag in self.all_data:
            # Recherche dans PID, Nom, IP, Org
            content = f"{vals[0]} {vals[1]} {vals[2]} {vals[4]}".lower()
            if query in content:
                self.tree.insert("", "end", iid=iid, values=vals, tags=(tag,))

    def show_details(self):
        """Affiche une fenêtre popup avec les détails"""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Détails", "Veuillez sélectionner une ligne.")
            return

        vals = self.tree.item(sel[0])['values']

        win = tk.Toplevel(self.root)
        win.title(f"Détails : {vals[1]}")
        win.geometry("500x450")
        win.configure(bg=THEME["bg_panel"])

        tk.Label(win, text=f"APP : {vals[1]}", bg=THEME["bg_panel"], fg=THEME["accent"], font=THEME["font_title"]).pack(
            pady=10)

        info_frame = tk.Frame(win, bg=THEME["bg_panel"], padx=20)
        info_frame.pack(fill="both", expand=True)

        # Mappage des données
        infos = [
            ("ID Processus (PID)", vals[0]),
            ("Chemin Exécutable", vals[8]),
            ("IP Distante", vals[2]),
            ("Port Distant", vals[3]),
            ("Organisation/ISP", vals[4]),
            ("Données Envoyées (Total)", vals[5]),
            ("Données Reçues (Total)", vals[6]),
            ("Temps d'Activité", vals[7]),
            ("État Sécurité",
             "RÈGLE DE BLOCAGE ACTIVE" if "blocked" in self.tree.item(sel[0], "tags") else "ACTIF / AUTORISÉ")
        ]

        for label, value in infos:
            row = tk.Frame(info_frame, bg=THEME["bg_panel"], pady=5)
            row.pack(fill="x")
            tk.Label(row, text=label + ":", width=20, anchor="w", bg=THEME["bg_panel"], fg=THEME["fg_secondary"],
                     font=("Segoe UI", 9)).pack(side="left")
            tk.Label(row, text=str(value), bg=THEME["bg_panel"], fg="white", font=("Consolas", 9), wraplength=300,
                     justify="left").pack(side="left")

        tk.Button(win, text="Fermer", command=win.destroy, bg=THEME["accent"], fg="black").pack(pady=20)

    # --- ACTIONS ---

    def block_app(self):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])['values']
        path, name = vals[8], vals[1]

        if messagebox.askyesno("Confirmer le Blocage",
                               f"Voulez-vous vraiment bloquer l'accès réseau (Entrée/Sortie) pour :\n{name} ?"):
            if SystemFirewall.block_executable(path):
                messagebox.showinfo("Succès",
                                    f" {name} est maintenant bloqué. L'état sera mis à jour dans le tableau.")
                self.refresh_connections()
            else:
                messagebox.showerror("Erreur", "Échec du blocage. Vérifiez les droits système.")

    def unblock_app(self):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])['values']
        path = vals[8]

        if messagebox.askyesno("Confirmer le Déblocage", f"Voulez-vous rétablir l'accès réseau pour {vals[1]} ?"):
            if SystemFirewall.unblock_executable(path):
                messagebox.showinfo("Succès", " Accès réseau rétabli.")
                self.refresh_connections()
            else:
                messagebox.showerror("Erreur", "Impossible de supprimer la règle.")


# --- POINT D'ENTRÉE UNIQUE ---
if __name__ == "__main__":
    if not is_admin():
        try:
            if len(sys.argv) == 1 or sys.argv[-1] != "as_admin":
                params = " ".join([f'"{a}"' for a in sys.argv] + ["as_admin"])
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
                sys.exit()
        except Exception:
            sys.exit()

    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()