#!/usr/bin/env python3
"""
ArchLink - Server Switcher
Outil pour changer facilement de serveur en modifiant le fichier Archlord.ini chiffré
"""

import os
import sys
import json
import hashlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from pathlib import Path

# Configuration par défaut
DEFAULT_CONFIG = {
    "servers": [
        {"name": "Sylvania (Local)", "ip": "192.168.1.14", "port": "11002"},
        {"name": "Archonia", "ip": "51.178.52.11", "port": "11002"},
    ],
    "game_path": "",
    "last_server": ""
}

CONFIG_FILE = "server_switcher_config.json"


def get_app_dir() -> Path:
    """Retourne le répertoire de l'application (où se trouve l'exe ou le script)"""
    if getattr(sys, 'frozen', False):
        # Exécutable PyInstaller
        return Path(sys.executable).parent
    else:
        # Script Python
        return Path(__file__).parent


def get_config_path() -> Path:
    """Retourne le chemin complet du fichier de configuration"""
    return get_app_dir() / CONFIG_FILE


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    """RC4 encryption/decryption (symmetric)"""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    
    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
    
    return bytes(result)


def derive_key(password: str = "1111") -> bytes:
    """Derive RC4 key from password using MD5"""
    return hashlib.md5(password.encode('ascii')).digest()


def decrypt_ini(file_path: str) -> str:
    """Déchiffre un fichier Archlord.ini"""
    key = derive_key()
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = rc4_crypt(encrypted_data, key)
    try:
        return decrypted_data.decode('utf-8')
    except:
        return decrypted_data.decode('latin-1')


def encrypt_ini(content: str, file_path: str):
    """Chiffre et sauvegarde un fichier Archlord.ini"""
    key = derive_key()
    plaintext = content.encode('utf-8')
    encrypted_data = rc4_crypt(plaintext, key)
    with open(file_path, 'wb') as f:
        f.write(encrypted_data)


def create_ini_content(server_name: str, ip: str, port: str) -> str:
    """Crée le contenu XML du fichier Archlord.ini"""
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<IPInfo>	
	<ServerGroup>
		<GroupName>{server_name}</GroupName>
		<IP>{ip}:{port}</IP>
	</ServerGroup>	
</IPInfo>
'''


class ServerSwitcherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ArchLink")
        self.root.geometry("500x620")
        self.root.resizable(False, False)
        
        # Définir l'icône de la fenêtre (barre de titre + barre des tâches)
        self.set_window_icon()
        
        # Configuration
        self.config = self.load_config()
        
        # Style
        self.setup_style()
        
        # UI
        self.create_widgets()
        
        # Charger le serveur actuel
        self.refresh_current_server()
    
    def set_window_icon(self):
        """Définit l'icône de la fenêtre et de la barre des tâches"""
        try:
            # Chemin de l'icône
            app_dir = get_app_dir()
            ico_path = app_dir / "icon.ico"
            png_path = app_dir / "archlink_logo.png"
            
            # Essayer d'utiliser le fichier ICO
            if ico_path.exists():
                self.root.iconbitmap(str(ico_path))
            elif png_path.exists():
                # Utiliser le PNG comme icône (nécessite PhotoImage)
                icon = tk.PhotoImage(file=str(png_path))
                self.root.iconphoto(True, icon)
        except Exception as e:
            print(f"[DEBUG] Impossible de charger l'icône: {e}")
    
    def load_logo_image(self):
        """Charge l'image du logo pour l'afficher dans l'interface"""
        try:
            from PIL import Image, ImageTk
            
            app_dir = get_app_dir()
            png_path = app_dir / "archlink_logo.png"
            
            if png_path.exists():
                # Charger et redimensionner l'image
                img = Image.open(png_path)
                # Calculer la nouvelle taille en gardant le ratio
                max_width = 150
                ratio = max_width / img.width
                new_height = int(img.height * ratio)
                img = img.resize((max_width, new_height), Image.Resampling.LANCZOS)
                return ImageTk.PhotoImage(img)
        except Exception as e:
            print(f"[DEBUG] Impossible de charger le logo: {e}")
        return None
    
    def setup_style(self):
        """Configure le style de l'application"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Couleurs
        self.bg_color = "#1a1a2e"
        self.fg_color = "#eee"
        self.accent_color = "#d4af37"
        self.button_color = "#16213e"
        
        self.root.configure(bg=self.bg_color)
        
        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, foreground=self.fg_color, font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground=self.accent_color)
        style.configure("Status.TLabel", font=("Segoe UI", 11), foreground="#aaa")
        style.configure("Current.TLabel", font=("Segoe UI", 12, "bold"), foreground="#4CAF50")
        style.configure("TButton", font=("Segoe UI", 10))
        style.configure("Accent.TButton", font=("Segoe UI", 11, "bold"))
        style.configure("TEntry", font=("Segoe UI", 10))
        style.configure("TCombobox", font=("Segoe UI", 10))
    
    def load_config(self) -> dict:
        """Charge la configuration depuis le fichier JSON"""
        config_path = get_config_path()
        print(f"[DEBUG] Config path: {config_path}")
        
        if config_path.exists():
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    print(f"[DEBUG] Config loaded: {len(config.get('servers', []))} servers")
                    return config
            except Exception as e:
                print(f"[DEBUG] Error loading config: {e}")
        return DEFAULT_CONFIG.copy()
    
    def save_config(self):
        """Sauvegarde la configuration"""
        config_path = get_config_path()
        try:
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
            print(f"[DEBUG] Config saved to {config_path}")
        except Exception as e:
            print(f"[DEBUG] Error saving config: {e}")
            messagebox.showerror("Erreur", f"Impossible de sauvegarder la config:\n{e}")
    
    def create_widgets(self):
        """Crée les widgets de l'interface"""
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Logo (image au lieu de texte)
        self.logo_image = self.load_logo_image()
        if self.logo_image:
            logo_label = ttk.Label(main_frame, image=self.logo_image, background=self.bg_color)
            logo_label.pack(pady=(0, 10))
        else:
            # Fallback si l'image n'est pas trouvée
            title_label = ttk.Label(main_frame, text="ArchLink", style="Title.TLabel")
            title_label.pack(pady=(0, 20))
        
        # Chemin du jeu
        path_frame = ttk.Frame(main_frame)
        path_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(path_frame, text="📁 Fichier Archlord.ini:").pack(anchor=tk.W)
        
        path_entry_frame = ttk.Frame(path_frame)
        path_entry_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.path_var = tk.StringVar(value=self.config.get("game_path", ""))
        self.path_entry = ttk.Entry(path_entry_frame, textvariable=self.path_var, width=45)
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        browse_btn = ttk.Button(path_entry_frame, text="...", width=3, command=self.browse_path)
        browse_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Serveur actuel
        current_frame = ttk.Frame(main_frame)
        current_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(current_frame, text="🌐 Serveur actuel:").pack(anchor=tk.W)
        self.current_server_label = ttk.Label(current_frame, text="Non détecté", style="Current.TLabel")
        self.current_server_label.pack(anchor=tk.W, pady=(5, 0))
        
        # Sélection du serveur
        server_frame = ttk.Frame(main_frame)
        server_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(server_frame, text="🎯 Changer vers:").pack(anchor=tk.W)
        
        self.server_var = tk.StringVar()
        self.server_combo = ttk.Combobox(server_frame, textvariable=self.server_var, state="readonly", width=40)
        self.update_server_list()
        self.server_combo.pack(anchor=tk.W, pady=(5, 0))
        
        # Bouton de changement
        switch_btn = ttk.Button(main_frame, text="🔄 Changer de Serveur", command=self.switch_server, style="Accent.TButton")
        switch_btn.pack(pady=(10, 20))
        
        # Séparateur
        ttk.Separator(main_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=10)
        
        # Gestion des serveurs
        manage_frame = ttk.Frame(main_frame)
        manage_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(manage_frame, text="➕ Ajouter un serveur:").pack(anchor=tk.W)
        
        add_frame = ttk.Frame(manage_frame)
        add_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Label(add_frame, text="Nom:").grid(row=0, column=0, sticky=tk.W)
        self.new_name_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.new_name_var, width=15).grid(row=0, column=1, padx=5)
        
        ttk.Label(add_frame, text="IP:").grid(row=0, column=2, sticky=tk.W)
        self.new_ip_var = tk.StringVar()
        ttk.Entry(add_frame, textvariable=self.new_ip_var, width=15).grid(row=0, column=3, padx=5)
        
        ttk.Label(add_frame, text="Port:").grid(row=0, column=4, sticky=tk.W)
        self.new_port_var = tk.StringVar(value="11002")
        ttk.Entry(add_frame, textvariable=self.new_port_var, width=6).grid(row=0, column=5, padx=5)
        
        add_btn = ttk.Button(add_frame, text="➕", width=3, command=self.add_server)
        add_btn.grid(row=0, column=6, padx=5)
        
        # Bouton supprimer
        delete_frame = ttk.Frame(main_frame)
        delete_frame.pack(fill=tk.X, pady=(10, 0))
        
        delete_btn = ttk.Button(delete_frame, text="🗑️ Supprimer le serveur sélectionné", command=self.delete_server)
        delete_btn.pack(side=tk.LEFT)
        
        refresh_btn = ttk.Button(delete_frame, text="🔃 Rafraîchir", command=self.refresh_current_server)
        refresh_btn.pack(side=tk.RIGHT)
    
    def browse_path(self):
        """Ouvre le dialogue pour sélectionner le fichier Archlord.ini"""
        path = filedialog.askopenfilename(
            title="Sélectionner le fichier Archlord.ini",
            filetypes=[("Fichier INI", "*.ini"), ("Tous les fichiers", "*.*")],
            initialfile="Archlord.ini"
        )
        if path:
            self.path_var.set(path)
            self.config["game_path"] = path
            self.save_config()
            self.refresh_current_server()
    
    def get_ini_path(self) -> str:
        """Retourne le chemin du fichier Archlord.ini"""
        return self.path_var.get()
    
    def refresh_current_server(self):
        """Lit et affiche le serveur actuel"""
        ini_path = self.get_ini_path()
        
        if not ini_path or not os.path.exists(ini_path):
            self.current_server_label.config(text="⚠️ Fichier non trouvé")
            return
        
        try:
            content = decrypt_ini(ini_path)
            # Parser le XML basique
            if "<IP>" in content and "</IP>" in content:
                start = content.find("<IP>") + 4
                end = content.find("</IP>")
                ip_port = content[start:end]
                
                # Chercher le nom dans notre config
                server_name = "Inconnu"
                for server in self.config["servers"]:
                    if f"{server['ip']}:{server['port']}" == ip_port:
                        server_name = server["name"]
                        break
                
                self.current_server_label.config(text=f"✅ {server_name} ({ip_port})")
            else:
                self.current_server_label.config(text="⚠️ Format non reconnu")
        except Exception as e:
            self.current_server_label.config(text=f"❌ Erreur: {str(e)[:30]}")
    
    def update_server_list(self):
        """Met à jour la liste des serveurs dans le combobox"""
        servers = [f"{s['name']} ({s['ip']}:{s['port']})" for s in self.config["servers"]]
        self.server_combo['values'] = servers
        if servers:
            self.server_combo.current(0)
    
    def switch_server(self):
        """Change le serveur actuel"""
        ini_path = self.get_ini_path()
        
        if not ini_path:
            messagebox.showerror("Erreur", "Veuillez sélectionner le dossier Game d'Archlord")
            return
        
        if not os.path.exists(ini_path):
            messagebox.showerror("Erreur", f"Fichier non trouvé:\n{ini_path}")
            return
        
        selected_idx = self.server_combo.current()
        if selected_idx < 0:
            messagebox.showerror("Erreur", "Veuillez sélectionner un serveur")
            return
        
        server = self.config["servers"][selected_idx]
        
        try:
            # Créer le nouveau contenu
            new_content = create_ini_content(server["name"], server["ip"], server["port"])
            
            # Sauvegarder avec chiffrement
            encrypt_ini(new_content, ini_path)
            
            self.config["last_server"] = server["name"]
            self.save_config()
            
            self.refresh_current_server()
            messagebox.showinfo("Succès", f"✅ Serveur changé vers:\n{server['name']}\n({server['ip']}:{server['port']})")
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Échec du changement:\n{str(e)}")
    
    def add_server(self):
        """Ajoute un nouveau serveur"""
        name = self.new_name_var.get().strip()
        ip = self.new_ip_var.get().strip()
        port = self.new_port_var.get().strip() or "11002"
        
        if not name or not ip:
            messagebox.showerror("Erreur", "Veuillez remplir le nom et l'IP")
            return
        
        self.config["servers"].append({"name": name, "ip": ip, "port": port})
        self.save_config()
        self.update_server_list()
        
        # Effacer les champs
        self.new_name_var.set("")
        self.new_ip_var.set("")
        self.new_port_var.set("11002")
        
        messagebox.showinfo("Succès", f"Serveur '{name}' ajouté!")
    
    def delete_server(self):
        """Supprime le serveur sélectionné"""
        selected_idx = self.server_combo.current()
        if selected_idx < 0:
            messagebox.showerror("Erreur", "Veuillez sélectionner un serveur à supprimer")
            return
        
        server = self.config["servers"][selected_idx]
        
        if messagebox.askyesno("Confirmation", f"Supprimer le serveur '{server['name']}'?"):
            del self.config["servers"][selected_idx]
            self.save_config()
            self.update_server_list()


def main():
    root = tk.Tk()
    app = ServerSwitcherApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
