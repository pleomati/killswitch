import threading
import time
import winsound
import psutil
import socket
import tkinter as tk
from tkinter import ttk, messagebox
import logging
import subprocess
from typing import Optional, List
import ipaddress

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='killswitch.log',
    filemode='a'
)

LOGO = """
 __   .__.__  .__                  .__  __         .__     
|  | _|__|  | |  |   ________  _  _|__|/  |_  ____ |  |__  
|  |/ /  |  | |  |  /  ___/\\ \\/ \\/ /  \\   __\\/ ___\\|  |  \\ 
|    <|  |  |_|  |__\\___ \\  \\     /|  ||  | \\  \\___|   Y   \\
|__|_ \\__|____/____/____  >  \\/\\_/ |__||__|  \\___  >___|   /
     \\/                 \\/                       \\/     \\/ 
"""

class DarkTheme:
    BACKGROUND = "#1e1e1e"
    FOREGROUND = "#e0e0e0"
    ACCENT = "#4a90e2"
    WARNING = "#ff6b6b"
    SUCCESS = "#6bff6b"
    FRAME = "#2d2d2d"
    TEXT = "#ffffff"
    BUTTON = "#3a3a3a"
    BUTTON_ACTIVE = "#4a4a4a"
    ENTRY = "#252525"
    COMBOBOX = "#252525"
    DISABLED = "#5a5a5a"

class VPNDetector:
    # Typowe zakresy IP używane przez VPN
    VPN_IP_RANGES = [
        "10.0.0.0/8",          # Private network range
        "172.16.0.0/12",       # Private network range
        "192.168.0.0/16",      # Private network range
        "100.64.0.0/10",       # Shared Address Space (CGNAT)
        "192.0.2.0/24",       # TEST-NET-1
        "198.18.0.0/15",      # Network interconnect device benchmark testing
        "198.51.100.0/24",    # TEST-NET-2
        "203.0.113.0/24",     # TEST-NET-3
    ]
    
    # Typowe nazwy interfejsów VPN
    VPN_INTERFACE_NAMES = [
        'vpn', 'tun', 'TAP', 'wireguard', 'openvpn', 
        'TAP-Windows', 'openvpn-tun', 'pptp', 'l2tp', 
        'ipsec', 'zerotier', 'tailscale', 'nordvpn', 
        'expressvpn', 'protonvpn', 'surfshark'
    ]
    
    @classmethod
    def is_vpn_ip(cls, ip_address: str) -> bool:
        """Sprawdza czy adres IP należy do typowych zakresów VPN."""
        try:
            ip = ipaddress.ip_address(ip_address)
            for network in cls.VPN_IP_RANGES:
                if ip in ipaddress.ip_network(network):
                    return True
        except ValueError:
            return False
        return False
    
    @classmethod
    def is_vpn_interface(cls, interface_name: str) -> bool:
        """Sprawdza czy nazwa interfejsu sugeruje że to VPN."""
        interface_lower = interface_name.lower()
        return any(vpn_name in interface_lower for vpn_name in cls.VPN_INTERFACE_NAMES)

class KillswitchApp:
    def __init__(self, root: tk.Tk):
        """Inicjalizacja aplikacji Killswitch VPN."""
        self.root = root
        self.setup_window()
        self.setup_style()
        self.vpn_nic: Optional[str] = None
        self.is_kill: bool = False
        self.kill_event = threading.Event()
        self.create_widgets()
        
    def setup_window(self) -> None:
        """Konfiguracja głównego okna."""
        self.root.title("Killswitch VPN")
        self.root.geometry("520x540")
        self.root.minsize(520, 540)
        self.root.configure(bg=DarkTheme.BACKGROUND)
        try:
            self.root.iconbitmap('icon.ico')
        except Exception:
            pass
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_style(self) -> None:
        """Konfiguracja ciemnego motywu."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Styl ogólny
        style.configure('.', 
                      background=DarkTheme.BACKGROUND,
                      foreground=DarkTheme.TEXT,
                      fieldbackground=DarkTheme.ENTRY,
                      selectbackground=DarkTheme.ACCENT,
                      selectforeground=DarkTheme.TEXT,
                      insertcolor=DarkTheme.TEXT,
                      troughcolor=DarkTheme.FRAME)
        
        # Ramki
        style.configure('TFrame', background=DarkTheme.BACKGROUND)
        style.configure('TLabelframe', 
                      background=DarkTheme.FRAME,
                      foreground=DarkTheme.ACCENT,
                      bordercolor=DarkTheme.FRAME,
                      relief='flat',
                      padding=10)
        
        # Przyciski
        style.configure('TButton',
                      background=DarkTheme.BUTTON,
                      foreground=DarkTheme.TEXT,
                      bordercolor=DarkTheme.BUTTON,
                      focusthickness=0,
                      focuscolor='none',
                      padding=8,
                      font=('Segoe UI', 9),
                      relief='flat')
        style.map('TButton',
                background=[('active', DarkTheme.BUTTON_ACTIVE)],
                foreground=[('active', DarkTheme.TEXT)],
                bordercolor=[('active', DarkTheme.BUTTON_ACTIVE)])
        
        # Przycisk akcentowany
        style.configure('Accent.TButton',
                      background=DarkTheme.ACCENT,
                      foreground=DarkTheme.TEXT)
        
        # Etykiety
        style.configure('TLabel',
                      background=DarkTheme.BACKGROUND,
                      foreground=DarkTheme.TEXT,
                      font=('Segoe UI', 9))

    def create_widgets(self) -> None:
        """Tworzenie interfejsu użytkownika."""
        # Główna ramka
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Logo
        logo_frame = ttk.Frame(main_frame)
        logo_frame.pack(pady=(0, 15))
        
        logo_label = tk.Label(
            logo_frame, 
            text=LOGO, 
            fg=DarkTheme.ACCENT, 
            bg=DarkTheme.BACKGROUND,
            font=("Consolas", 9)
        )
        logo_label.pack()

        # Sekcja wyboru interfejsu
        interface_frame = ttk.LabelFrame(
            main_frame, 
            text="Interface Selection",
            padding=(15, 10)
        )
        interface_frame.pack(fill=tk.X, pady=5)

        self.interface_label = ttk.Label(
            interface_frame, 
            text="Selected interface: None",
            font=('Segoe UI', 9),
            foreground=DarkTheme.SUCCESS
        )
        self.interface_label.pack(pady=(0, 10), anchor=tk.W)

        btn_frame = ttk.Frame(interface_frame)
        btn_frame.pack(fill=tk.X, pady=5)

        select_btn = ttk.Button(
            btn_frame, 
            text="Select Interface", 
            command=self.select_interface_gui,
            width=15
        )
        select_btn.pack(side=tk.LEFT, padx=5)

        auto_detect_btn = ttk.Button(
            btn_frame,
            text="Auto Detect",
            command=self.auto_detect_interface,
            width=15
        )
        auto_detect_btn.pack(side=tk.LEFT, padx=5)

        # Sekcja statusu
        status_frame = ttk.LabelFrame(
            main_frame, 
            text="Status",
            padding=(15, 10)
        )
        status_frame.pack(fill=tk.X, pady=5)

        self.status_label = ttk.Label(
            status_frame, 
            text="Status: Inactive",
            font=('Segoe UI', 9),
            foreground=DarkTheme.WARNING
        )
        self.status_label.pack(pady=(0, 5), anchor=tk.W)

        # Przyciski kontrolne
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=15)

        self.start_button = ttk.Button(
            control_frame, 
            text="Start Monitoring", 
            command=self.start_killswitch,
            style='Accent.TButton',
            width=20
        )
        self.start_button.pack(side=tk.LEFT, padx=5, expand=True)

        self.stop_button = ttk.Button(
            control_frame, 
            text="Stop Monitoring", 
            command=self.stop_killswitch,
            state=tk.DISABLED,
            width=20
        )
        self.stop_button.pack(side=tk.LEFT, padx=5, expand=True)

        # Sekcja informacyjna
        info_frame = ttk.LabelFrame(
            main_frame, 
            text="Information",
            padding=(15, 10)
        )
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.info_label = ttk.Label(
            info_frame, 
            text="Welcome to Killswitch VPN\nSelect an interface to begin",
            wraplength=450,
            justify=tk.LEFT,
            font=('Segoe UI', 9)
        )
        self.info_label.pack(pady=5, padx=5, fill=tk.BOTH, expand=True)

    def select_interface_gui(self) -> None:
        """Obsługa wyboru interfejsu przez GUI."""
        if self.select_interface():
            self.update_interface_display()
            self.update_info(f"Selected interface: {self.vpn_nic}")

    def auto_detect_interface(self) -> None:
        """Automatyczne wykrywanie interfejsu VPN."""
        # Najpierw spróbuj wykryć po nazwie
        vpn_interface = self.detect_vpn_interface_by_name()
        
        # Jeśli nie znaleziono, spróbuj po adresie IP
        if not vpn_interface:
            vpn_interface = self.detect_vpn_interface_by_ip()
        
        if vpn_interface:
            self.vpn_nic = vpn_interface
            self.update_interface_display()
            self.update_info(f"Auto-detected VPN interface: {vpn_interface}")
            messagebox.showinfo(
                "Auto Detection",
                f"VPN interface detected:\n{vpn_interface}\n\n"
                f"IP addresses: {', '.join(self.get_interface_ips(vpn_interface))}"
            )
        else:
            messagebox.showwarning(
                "Auto Detection Failed",
                "Could not automatically detect VPN interface.\n"
                "Please select manually."
            )

    def detect_vpn_interface_by_name(self) -> Optional[str]:
        """Wykrywanie VPN po nazwie interfejsu."""
        for name in psutil.net_if_addrs():
            if VPNDetector.is_vpn_interface(name):
                return name
        return None

    def detect_vpn_interface_by_ip(self) -> Optional[str]:
        """Wykrywanie VPN po zakresie adresów IP."""
        potential_vpns = []
        
        for name, addrs in psutil.net_if_addrs().items():
            # Pomiń interfejsy loopback i nieaktywne
            if name == 'lo' or not self.get_interface_status(name):
                continue
                
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6):
                    if VPNDetector.is_vpn_ip(addr.address):
                        potential_vpns.append(name)
                        break
        
        if not potential_vpns:
            return None
            
        # Priorytet dla interfejsów niebędących Ethernet/Wi-Fi
        for iface in potential_vpns:
            iface_lower = iface.lower()
            if 'ether' not in iface_lower and 'wi-fi' not in iface_lower and 'wlan' not in iface_lower:
                return iface
                
        return potential_vpns[0]

    def update_interface_display(self) -> None:
        """Aktualizacja wyświetlanych informacji o interfejsie."""
        if self.vpn_nic:
            status = "Enabled" if self.get_interface_status(self.vpn_nic) else "Disabled"
            color = DarkTheme.SUCCESS if status == "Enabled" else DarkTheme.WARNING
            self.interface_label.config(
                text=f"Selected interface: {self.vpn_nic} ({status})",
                foreground=color
            )
            ips = self.get_interface_ips(self.vpn_nic)
            if isinstance(ips, list):
                ip_text = ", ".join(ips)
                self.interface_label.config(
                    text=f"Selected interface: {self.vpn_nic} ({status})\nIPs: {ip_text}",
                    foreground=color
                )

    def select_interface(self) -> bool:
        """Ręczny wybór interfejsu sieciowego."""
        adapters = list(psutil.net_if_addrs().keys())

        if not adapters:
            messagebox.showerror(
                "Error", 
                "No network interfaces found."
            )
            return False

        dialog = tk.Toplevel(self.root)
        dialog.title("Select Network Interface")
        dialog.resizable(False, False)
        dialog.configure(bg=DarkTheme.BACKGROUND)
        
        # Wyśrodkowanie okna dialogowego
        dialog.geometry(f"400x200+{self.root.winfo_x()+50}+{self.root.winfo_y()+50}")

        ttk.Label(
            dialog, 
            text="Select your VPN interface:",
            font=('Segoe UI', 10, 'bold')
        ).pack(pady=10)

        combo = ttk.Combobox(
            dialog, 
            values=adapters, 
            state="readonly",
            font=('Segoe UI', 9),
            height=15
        )
        combo.pack(pady=10, padx=20, fill=tk.X)
        combo.current(0)

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(pady=10)

        def on_ok():
            self.vpn_nic = combo.get()
            dialog.destroy()

        ttk.Button(
            btn_frame, 
            text="OK", 
            command=on_ok,
            width=10
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            btn_frame, 
            text="Cancel", 
            command=dialog.destroy,
            width=10
        ).pack(side=tk.LEFT, padx=10)

        dialog.transient(self.root)
        dialog.grab_set()
        self.root.wait_window(dialog)

        return bool(self.vpn_nic)

    def start_killswitch(self) -> None:
        """Uruchomienie monitorowania interfejsu."""
        if not self.vpn_nic:
            messagebox.showwarning(
                "Warning", 
                "Please select a network interface first."
            )
            return

        self.is_kill = False
        self.kill_event.clear()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(
            text="Status: Active - Monitoring",
            foreground=DarkTheme.SUCCESS
        )
        self.update_info("Killswitch activated. Monitoring network interface...")

        monitor_thread = threading.Thread(
            target=self.monitor_network_changes, 
            daemon=True
        )
        monitor_thread.start()

        messagebox.showinfo(
            "Killswitch Active",
            "Network monitoring started.\n"
            "The killswitch will disable internet if the VPN connection drops."
        )

    def stop_killswitch(self) -> None:
        """Zatrzymanie monitorowania interfejsu."""
        logging.info("Killswitch monitoring stopped by user.")
        self.is_kill = True
        self.kill_event.set()
        
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)
        self.status_label.config(
            text="Status: Inactive",
            foreground=DarkTheme.WARNING
        )
        self.update_info("Killswitch deactivated.")

        messagebox.showinfo(
            "Killswitch Inactive",
            "Network monitoring stopped."
        )

    def monitor_network_changes(self) -> None:
        """Monitorowanie zmian w interfejsie sieciowym."""
        last_status = self.get_interface_status(self.vpn_nic)
        
        while not self.kill_event.is_set():
            current_status = self.get_interface_status(self.vpn_nic)
            
            if current_status != last_status:
                status_text = "Enabled" if current_status else "Disabled"
                logging.info(
                    f"Interface status changed to: {status_text}"
                )
                self.root.after(0, self.update_interface_display)
                self.address_changed_callback()
                last_status = current_status
            
            time.sleep(1)
        
        logging.info("Network monitoring thread stopped.")

    def address_changed_callback(self) -> None:
        """Reakcja na zmianę statusu interfejsu."""
        if not self.is_kill:
            # Dźwięk ostrzegawczy
            for _ in range(3):
                winsound.Beep(570, 100)
                time.sleep(0.1)
            
            logging.warning("Network change detected. Checking VPN status...")
            
            adapters = list(psutil.net_if_addrs().keys())
            if self.vpn_nic not in adapters or not self.get_interface_status(self.vpn_nic):
                self.is_kill = True
                self.kill_now()
                logging.error(
                    "VPN connection lost! Internet access has been disabled.\n"
                    "Please restart the killswitch after reconnecting your VPN."
                )

    def kill_now(self) -> None:
        """Wyłączenie połączenia internetowego."""
        try:
            self.update_info("VPN connection lost! Disabling internet...")
            
            # Zwolnienie adresu IP (Windows)
            subprocess.run(
                ["ipconfig", "/release"],
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                check=True
            )
            
            messagebox.showerror(
                "VPN Disconnected",
                "Your VPN connection was lost!\n"
                "Internet access has been disabled for security.\n\n"
                "Please reconnect your VPN and restart the killswitch."
            )
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to disable internet: {e}"
            logging.error(error_msg)
            self.update_info(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error: {e}"
            logging.exception(error_msg)
            self.update_info(error_msg)

    def get_interface_status(self, interface_name: str) -> bool:
        """Sprawdzenie czy interfejs jest aktywny."""
        try:
            stats = psutil.net_if_stats()
            return interface_name in stats and stats[interface_name].isup
        except Exception as e:
            logging.error(f"Error checking interface status: {e}")
            return False

    def get_interface_ips(self, interface_name: str) -> List[str]:
        """Pobranie adresów IP przypisanych do interfejsu."""
        try:
            addrs = psutil.net_if_addrs().get(interface_name, [])
            return [
                addr.address for addr in addrs 
                if addr.family in (socket.AF_INET, socket.AF_INET6)
            ]
        except Exception as e:
            logging.error(f"Error getting interface IPs: {e}")
            return []

    def update_info(self, message: str) -> None:
        """Aktualizacja informacji w interfejsie."""
        def _update():
            self.info_label.config(text=message)
        self.root.after(0, _update)

    def on_closing(self) -> None:
        """Obsługa zamknięcia aplikacji."""
        if messagebox.askokcancel(
            "Quit",
            "Are you sure you want to quit?\n"
            "This will stop the killswitch monitoring."
        ):
            self.stop_killswitch()
            self.root.destroy()

def main():
    """Główna funkcja uruchamiająca aplikację."""
    root = tk.Tk()
    
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except:
        pass
    
    app = KillswitchApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()