import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading
import time

class ServerDetectorApp:
    def __init__(self, root):
        self.root = root
        self.root.title(" KOMRAD TACACS+ / RADIUS")
        self.root.title(" 🐍 DETECTOR DE SISTEMAS TACACS+/RADIUS 🐍 ")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Variables
        self.target_ip = tk.StringVar()
        self.ports = tk.StringVar(value="49,1812,1813,1645,1646")
        self.scanning = False
        
        self.setup_ui()
        
    def setup_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configurar grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Título
        title_label = ttk.Label(main_frame, text=" KOMRAD TACACS+ / RADIUS ", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Campo de dirección IP
        ttk.Label(main_frame, text="Dirección IP:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ip_entry = ttk.Entry(main_frame, textvariable=self.target_ip, width=20)
        ip_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        
        # Campo de puertos
        ttk.Label(main_frame, text="Puertos:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ports_entry = ttk.Entry(main_frame, textvariable=self.ports, width=30)
        ports_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=5, padx=(5, 0))
        ttk.Label(main_frame, text="(separados por coma)").grid(row=2, column=2, sticky=tk.W, pady=5, padx=(5, 0))
        
        # Botones
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=3, pady=20)
        
        self.scan_button = ttk.Button(button_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_button = ttk.Button(button_frame, text="Detener Escaneo", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(button_frame, text="Limpiar", command=self.clear_results).pack(side=tk.LEFT)
        
        # Barra de progreso
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Área de resultados
        results_frame = ttk.LabelFrame(main_frame, text="Resultados", padding="5")
        results_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Treeview para mostrar resultados
        columns = ('Puerto', 'Estado', 'Servicio', 'Tipo', 'Respuesta')
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=12)
        
        # Configurar columnas
        self.results_tree.heading('Puerto', text='Puerto')
        self.results_tree.heading('Estado', text='Estado')
        self.results_tree.heading('Servicio', text='Servicio')
        self.results_tree.heading('Tipo', text='Tipo')
        self.results_tree.heading('Respuesta', text='Respuesta')
        
        self.results_tree.column('Puerto', width=80)
        self.results_tree.column('Estado', width=100)
        self.results_tree.column('Servicio', width=100)
        self.results_tree.column('Tipo', width=100)
        self.results_tree.column('Respuesta', width=200)
        
        # Scrollbar para el treeview
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configurar expansión
        main_frame.rowconfigure(5, weight=1)
        
    def parse_ports(self, ports_string):
        """Convierte el string de puertos a una lista"""
        ports = []
        for port in ports_string.split(','):
            port = port.strip()
            if '-' in port:
                try:
                    start, end = port.split('-')
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(port))
                except ValueError:
                    continue
        return ports
    
    def check_tacacs_port(self, port):
        """Puertos comunes para TACACS+"""
        return port in [49, 2089, 3089]
    
    def check_radius_port(self, port):
        """Puertos comunes para RADIUS"""
        return port in [1812, 1813, 1645, 1646, 2083, 2084]
    
    def test_port(self, ip, port, timeout=3):
        """Prueba la conectividad a un puerto específico"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                return True, "Conectado"
            else:
                return False, "Cerrado"
                
        except socket.gaierror:
            return False, "Error DNS"
        except socket.timeout:
            return False, "Timeout"
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def identify_service(self, port, is_open):
        """Identifica el tipo de servicio basado en el puerto"""
        if not is_open:
            return "Desconocido", "N/A"
            
        if self.check_tacacs_port(port):
            return "TACACS+", "Servidor de Autenticación"
        elif self.check_radius_port(port):
            if port in [1812, 1645]:
                return "RADIUS", "Servidor de Autenticación"
            elif port in [1813, 1646]:
                return "RADIUS", "Servidor de Contabilidad"
            else:
                return "RADIUS", "Servidor AAA"
        else:
            return "Otro", f"Puerto {port}"
    
    def scan_ports(self):
        """Ejecuta el escaneo de puertos en un hilo separado"""
        ip = self.target_ip.get().strip()
        ports_string = self.ports.get().strip()
        
        if not ip:
            messagebox.showerror("Error", "Por favor ingresa una dirección IP")
            return
        
        try:
            # Validar formato de IP
            socket.inet_aton(ip)
        except socket.error:
            messagebox.showerror("Error", "Dirección IP inválida")
            return
        
        ports = self.parse_ports(ports_string)
        if not ports:
            messagebox.showerror("Error", "No se pudieron parsear los puertos")
            return
        
        self.scanning = True
        self.progress.start()
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Limpiar resultados anteriores
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        total_ports = len(ports)
        current_port = 0
        
        for port in ports:
            if not self.scanning:
                break
                
            current_port += 1
            progress = (current_port / total_ports) * 100
            
            # Actualizar progreso en la interfaz
            self.root.after(0, self.update_progress_label, f"Escaneando puerto {port}...")
            
            # Probar el puerto
            is_open, status = self.test_port(ip, port)
            service_type, service_desc = self.identify_service(port, is_open)
            
            # Determinar el tipo de servidor
            server_type = "No identificado"
            if "TACACS+" in service_type:
                server_type = "TACACS+ Server"
            elif "RADIUS" in service_type:
                server_type = "RADIUS Server"
            
            # Añadir resultado al treeview
            self.root.after(0, self.add_result, port, status, service_type, server_type, service_desc)
            
            # Pequeña pausa para no saturar
            time.sleep(0.1)
        
        # Finalizar escaneo
        self.root.after(0, self.scan_complete)
    
    def update_progress_label(self, text):
        """Actualiza la barra de progreso"""
        self.progress.config(text=text)
    
    def add_result(self, port, status, service, server_type, response):
        """Añade un resultado al treeview"""
        # Color basado en el estado
        tags = ()
        if status == "Conectado":
            if "TACACS+" in service:
                tags = ('tacacs',)
            elif "RADIUS" in service:
                tags = ('radius',)
            else:
                tags = ('other',)
        
        self.results_tree.insert('', tk.END, values=(port, status, service, server_type, response), tags=tags)
    
    def start_scan(self):
        """Inicia el escaneo en un hilo separado"""
        scan_thread = threading.Thread(target=self.scan_ports)
        scan_thread.daemon = True
        scan_thread.start()
    
    def stop_scan(self):
        """Detiene el escaneo"""
        self.scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        messagebox.showinfo("Escaneo", "Escaneo detenido por el usuario")
    
    def scan_complete(self):
        """Limpia después de completar el escaneo"""
        self.scanning = False
        self.progress.stop()
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        messagebox.showinfo("Escaneo", "Escaneo completado")
    
    def clear_results(self):
        """Limpia los resultados"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)

def main():
    root = tk.Tk()
    app = ServerDetectorApp(root)
    
    # Configurar estilos para los resultados
    style = ttk.Style()
    style.configure('tacacs.Treeview', background='#e8f5e8')  # Verde claro para TACACS+
    style.configure('radius.Treeview', background='#e8f0f5')  # Azul claro para RADIUS
    style.configure('other.Treeview', background='#f5f5f5')   # Gris claro para otros
    
    # Asignar tags al treeview
    app.results_tree.tag_configure('tacacs', background='#e8f5e8')
    app.results_tree.tag_configure('radius', background='#e8f0f5')
    app.results_tree.tag_configure('other', background='#f5f5f5')
    
    root.mainloop()

if __name__ == "__main__":
    main()