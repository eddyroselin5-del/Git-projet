import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import socket

# Liste des règles de filtrage
rules = []

def ajouter_regle():
    ip = ip_entry.get()
    port = port_entry.get()
    protocole = protocole_var.get()
    action = action_var.get()

    if not ip or not port:
        messagebox.showerror("Erreur", "L'adresse IP et le port sont requis.")
        return

    try:
        port = int(port)
    except ValueError:
        messagebox.showerror("Erreur", "Le port doit être un nombre entier.")
        return

    regle = {"ip": ip, "port": port, "protocole": protocole, "action": action}
    rules.append(regle)
    afficher_regles()

def afficher_regles():
    tableau_regles.delete(*tableau_regles.get_children())
    for regle in rules:
        tableau_regles.insert("", "end", values=(regle["ip"], regle["port"], regle["protocole"], regle["action"]))

def analyser_connexion(conn):
    ip = conn.raddr.ip if conn.raddr else ""
    port = conn.raddr.port if conn.raddr else 0
    protocole = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"

    for regle in rules:
        if regle["ip"] == ip and regle["port"] == port and regle["protocole"] == protocole:
            return regle["action"]
    return "ALLOW"

def actualiser_connexions():
    tableau_connexions.delete(*tableau_connexions.get_children())
    for conn in psutil.net_connections(kind='inet'):
        if conn.status != "LISTEN" and conn.raddr:
            action = analyser_connexion(conn)
            tableau_connexions.insert("", "end", values=(
                conn.laddr.ip, conn.laddr.port,
                conn.raddr.ip, conn.raddr.port,
                conn.status, action
            ))

# Interface graphique
fenetre = tk.Tk()
fenetre.title("Pare-feu Réseau Python")

# Cadre pour ajouter une règle
cadre_regle = tk.LabelFrame(fenetre, text="Ajouter une règle")
cadre_regle.pack(fill="x", padx=10, pady=5)

tk.Label(cadre_regle, text="IP:").grid(row=0, column=0)
ip_entry = tk.Entry(cadre_regle)
ip_entry.grid(row=0, column=1)

tk.Label(cadre_regle, text="Port:").grid(row=0, column=2)
port_entry = tk.Entry(cadre_regle)
port_entry.grid(row=0, column=3)

tk.Label(cadre_regle, text="Protocole:").grid(row=0, column=4)
protocole_var = tk.StringVar(value="TCP")
tk.OptionMenu(cadre_regle, protocole_var, "TCP", "UDP").grid(row=0, column=5)

tk.Label(cadre_regle, text="Action:").grid(row=0, column=6)
action_var = tk.StringVar(value="BLOCK")
tk.OptionMenu(cadre_regle, action_var, "ALLOW", "BLOCK").grid(row=0, column=7)

tk.Button(cadre_regle, text="Ajouter", command=ajouter_regle).grid(row=0, column=8)

# Tableau des règles
tableau_regles = ttk.Treeview(fenetre, columns=("IP", "Port", "Protocole", "Action"), show="headings")
for col in tableau_regles["columns"]:
    tableau_regles.heading(col, text=col)
tableau_regles.pack(fill="x", padx=10, pady=5)

# Tableau des connexions actives
tk.Label(fenetre, text="Connexions réseau actives").pack()
tableau_connexions = ttk.Treeview(fenetre, columns=("IP locale", "Port local", "IP distante", "Port distant", "Statut", "Action"), show="headings")
for col in tableau_connexions["columns"]:
    tableau_connexions.heading(col, text=col)
tableau_connexions.pack(fill="both", expand=True, padx=10, pady=5)

tk.Button(fenetre, text="Actualiser", command=actualiser_connexions).pack(pady=5)

fenetre.mainloop()