import socket # Para operaciones de red, como establecer conexiones
import threading # Para ejecutar tareas en paralelo (hilos)
from queue import Queue # Para una cola segura entre hilos
import tkinter as tk # Módulo principal de Tkinter para la GUI
from tkinter import scrolledtext, messagebox # scrolledtext para área de texto con scroll, messagebox para mensajes de alerta

# --- Diccionarios de Datos ---

# Diccionario de puertos comunes y sus servicios asociados
COMMON_PORTS = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS Session Service",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP Proxy / Tomcat"
}

# Diccionario simple para simular sugerencias de vulnerabilidades
# Basadas en el servicio detectado (puedes expandirlo con más datos reales)
VULNERABILITY_SUGGESTIONS = {
    "SSH": [
        "Considerar deshabilitar el acceso SSH por contraseña y usar claves SSH para mayor seguridad.",
        "Asegurarse de que el servidor SSH esté actualizado a la última versión para parchear vulnerabilidades conocidas."
    ],
    "HTTP": [
        "Se recomienda implementar HTTPS (SSL/TLS) para cifrar el tráfico web y proteger la privacidad de los usuarios.",
        "Verificar que el servidor web no exponga información sensible (versión, directorios)."
    ],
    "FTP (Control)": [
        "Evitar el uso de FTP anónimo. Si es necesario, configurar permisos muy restrictivos.",
        "Considerar usar SFTP o FTPS para cifrar la transferencia de archivos."
    ],
    "Telnet": [
        "Telnet transmite datos sin cifrar. Se recomienda encarecidamente usar SSH en su lugar.",
        "Deshabilitar Telnet si no es estrictamente necesario."
    ],
    "SMB": [
        "Asegurarse de que SMB esté correctamente configurado y no exponga recursos compartidos innecesarios a la red pública.",
        "Mantener el servicio SMB actualizado para evitar vulnerabilidades como EternalBlue."
    ]
}

# --- Clase de la Aplicación GUI ---
class PortScannerGUI:
    def __init__(self, master):
        """
        Constructor de la clase. Configura la ventana principal de la GUI
        y sus elementos.
        """
        self.master = master # La ventana principal de Tkinter
        master.title("Port Scanner y Analizador de Vulnerabilidades") # Título de la ventana

        self.queue = Queue() # Cola para almacenar los puertos a escanear
        self.print_lock = threading.Lock() # Candado para proteger la salida en consola (no tan crítico con la GUI)
        self.is_scanning = False # Bandera para controlar si el escaneo está activo o no

        # --- Frame para los Campos de Entrada ---
        # Un frame es un contenedor para organizar widgets
        self.input_frame = tk.Frame(master, padx=10, pady=10)
        self.input_frame.pack(pady=5) # Empaca el frame en la ventana principal

        # Etiqueta y campo de entrada para el Host
        tk.Label(self.input_frame, text="Host a escanear:").grid(row=0, column=0, sticky="w", pady=2)
        self.target_host_entry = tk.Entry(self.input_frame, width=40)
        self.target_host_entry.grid(row=0, column=1, pady=2)
        self.target_host_entry.insert(0, "127.0.0.1") # Valor predeterminado (localhost)

        # Etiqueta y campo de entrada para el Puerto Inicial
        tk.Label(self.input_frame, text="Puerto inicial:").grid(row=1, column=0, sticky="w", pady=2)
        self.start_port_entry = tk.Entry(self.input_frame, width=10)
        self.start_port_entry.grid(row=1, column=1, sticky="w", pady=2)
        self.start_port_entry.insert(0, "1") # Valor predeterminado

        # Etiqueta y campo de entrada para el Puerto Final
        tk.Label(self.input_frame, text="Puerto final:").grid(row=2, column=0, sticky="w", pady=2)
        self.end_port_entry = tk.Entry(self.input_frame, width=10)
        self.end_port_entry.grid(row=2, column=1, sticky="w", pady=2)
        self.end_port_entry.insert(0, "1024") # Valor predeterminado

        # Etiqueta y campo de entrada para el Número de Hilos
        tk.Label(self.input_frame, text="Número de hilos:").grid(row=3, column=0, sticky="w", pady=2)
        self.num_threads_entry = tk.Entry(self.input_frame, width=10)
        self.num_threads_entry.grid(row=3, column=1, sticky="w", pady=2)
        self.num_threads_entry.insert(0, "50") # Valor predeterminado

        # Botón para Iniciar el Escaneo
        self.scan_button = tk.Button(self.input_frame, text="Iniciar Escaneo", command=self.start_scan)
        self.scan_button.grid(row=4, column=0, columnspan=2, pady=10)

        # --- Frame para los Resultados ---
        self.results_frame = tk.LabelFrame(master, text="Resultados del Escaneo y Análisis", padx=10, pady=10)
        self.results_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Área de texto desplazable (ScrolledText) para mostrar los resultados
        self.scan_output = scrolledtext.ScrolledText(self.results_frame, width=80, height=20, wrap=tk.WORD)
        self.scan_output.pack(expand=True, fill="both")

    def log_message(self, message):
        """
        Inserta un mensaje en el área de texto de salida de la GUI
        y hace scroll automáticamente al final.
        """
        self.scan_output.insert(tk.END, message + "\n") # Inserta el mensaje al final
        self.scan_output.see(tk.END) # Asegura que la última línea sea visible

    def port_scan(self, target_host, port):
        """
        Intenta conectarse a un puerto específico en el host objetivo.
        Si el puerto está abierto, registra el servicio y simula el análisis de vulnerabilidades.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Crea un socket TCP/IP
            sock.settimeout(1)  # Timeout de 1 segundo para la conexión (evita que se quede colgado)
            result = sock.connect_ex((target_host, port)) # Intenta conectar; connect_ex devuelve un código de error
            if result == 0: # Si el resultado es 0, el puerto está abierto
                service = COMMON_PORTS.get(port, "Unknown Service") # Obtiene el servicio del diccionario o "Unknown"
                self.log_message(f"Puerto {port} Abierto - Servicio: {service}") # Log en la GUI
                self.simulate_vulnerability_analysis(service, port) # Llama al simulador de vulnerabilidades
            sock.close() # Cierra el socket
        except socket.gaierror:
            # Error si el nombre de host no se puede resolver (ej. "dominio_inexistente")
            self.log_message(f"Error: No se pudo resolver el nombre de host '{target_host}'.")
            self.stop_scan() # Detiene el escaneo si el host no es válido
        except socket.error as e:
            # Captura otros errores de conexión (ej. "Connection refused" para puertos cerrados)
            # Solo muestra errores que no sean el típico "conexión rechazada" de un puerto cerrado
            if "Connection refused" not in str(e):
                self.log_message(f"Error de conexión en el puerto {port}: {e}")

    def simulate_vulnerability_analysis(self, service, port):
        """
        Simula un análisis de vulnerabilidades basándose en el servicio detectado.
        Muestra sugerencias de seguridad en la GUI.
        """
        if service in VULNERABILITY_SUGGESTIONS:
            self.log_message(f"  [Análisis de Vulnerabilidades - Sugerencias para {service} (Puerto {port})]:")
            for suggestion in VULNERABILITY_SUGGESTIONS[service]:
                self.log_message(f"    - {suggestion}")
        elif service != "Unknown Service": # Si no es un servicio conocido en nuestro diccionario, pero no es "Unknown"
            self.log_message(f"  [Análisis de Vulnerabilidades]: No hay sugerencias de seguridad específicas conocidas para {service} en este momento.")

    def worker(self, target_host):
        """
        Función que ejecuta cada hilo. Toma puertos de la cola y los escanea.
        """
        while self.is_scanning: # El hilo continúa trabajando mientras el escaneo esté activo
            try:
                # Intenta obtener un puerto de la cola con un timeout.
                # Esto permite que el hilo verifique 'is_scanning' periódicamente.
                port = self.queue.get(timeout=0.1)
                self.port_scan(target_host, port) # Escanea el puerto
                self.queue.task_done() # Marca la tarea como completada en la cola
            except Exception: # Si la cola está vacía, se dispara una excepción
                # Si el escaneo ya no está activo Y la cola está vacía, el hilo termina
                if not self.is_scanning and self.queue.empty():
                    break
                continue # Si el escaneo sigue activo o la cola no está vacía, intenta de nuevo

    def start_scan(self):
        """
        Valida las entradas del usuario y comienza el proceso de escaneo.
        Crea y arranca los hilos de trabajo.
        """
        if self.is_scanning: # Evita que se inicie un nuevo escaneo si ya hay uno en progreso
            messagebox.showinfo("Información", "Un escaneo ya está en progreso.")
            return

        # Obtiene los valores de los campos de entrada
        target_host = self.target_host_entry.get()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            num_threads = int(self.num_threads_entry.get())
        except ValueError: # Captura errores si los puertos o hilos no son números
            messagebox.showerror("Error de Entrada", "Por favor, introduce números válidos para los puertos y el número de hilos.")
            return

        # Validaciones básicas de los datos de entrada
        if not target_host:
            messagebox.showerror("Error de Entrada", "Por favor, introduce una dirección IP o nombre de host.")
            return
        if start_port <= 0 or end_port <= 0 or start_port > end_port:
            messagebox.showerror("Error de Entrada", "Por favor, introduce un rango de puertos válido (mayor que 0 y puerto inicial <= puerto final).")
            return
        if num_threads <= 0:
            messagebox.showerror("Error de Entrada", "El número de hilos debe ser mayor que 0.")
            return

        self.scan_output.delete(1.0, tk.END) # Limpia el área de resultados de escaneos anteriores
        self.log_message(f"Iniciando escaneo en {target_host} desde {start_port} hasta {end_port} con {num_threads} hilos...")
        self.is_scanning = True # Establece la bandera de escaneo a True
        self.scan_button.config(state=tk.DISABLED) # Deshabilita el botón de inicio durante el escaneo

        # Llena la cola con todos los puertos a escanear
        for port in range(start_port, end_port + 1):
            self.queue.put(port)

        # Inicia los hilos de trabajo
        self.threads = []
        for _ in range(num_threads):
            t = threading.Thread(target=self.worker, args=(target_host,))
            t.daemon = True  # Permite que el programa se cierre aunque los hilos estén corriendo
            self.threads.append(t)
            t.start()

        # Configura una llamada periódica a 'check_scan_completion' para monitorear el progreso del escaneo
        self.master.after(100, self.check_scan_completion)

    def check_scan_completion(self):
        """
        Verifica periódicamente si todas las tareas de escaneo han terminado.
        Se llama desde 'start_scan' y luego se auto-llama hasta que el escaneo finalice.
        """
        # Si el escaneo está activo Y la cola está vacía Y todos los hilos están inactivos/vacíos
        if self.is_scanning and self.queue.empty() and all(not t.is_alive() or self.queue.empty() for t in self.threads):
            # Da un pequeño retraso para asegurar que todos los logs se escriban
            self.master.after(500, self.finish_scan)
        elif self.is_scanning:
            self.master.after(100, self.check_scan_completion) # Vuelve a verificar después de un breve retraso

    def finish_scan(self):
        """
        Finaliza el escaneo, restablece la bandera y re-habilita el botón de inicio.
        """
        if self.is_scanning: # Asegura que solo se finalice si aún estaba activo
            self.is_scanning = False
            self.log_message("\nEscaneo de puertos completado.")
            self.scan_button.config(state=tk.NORMAL) # Re-habilita el botón de inicio

    def stop_scan(self):
        """
        Detiene un escaneo en progreso.
        Cambia la bandera 'is_scanning' y vacía la cola de puertos.
        """
        if self.is_scanning:
            self.is_scanning = False
            # Vacía la cola para que los hilos dejen de tomar nuevos puertos
            with self.queue.mutex: # Accede al mutex de la cola para modificarla de forma segura
                self.queue.queue.clear() # Limpia todos los elementos de la cola
            self.log_message("\nEscaneo detenido por el usuario.")
            self.scan_button.config(state=tk.NORMAL) # Re-habilita el botón de inicio

# --- Punto de Entrada de la Aplicación ---
if __name__ == "__main__":
    root = tk.Tk() # Crea la ventana principal de Tkinter
    app = PortScannerGUI(root) # Crea una instancia de nuestra clase GUI
    # Agrega un botón de "Detener Escaneo" para mayor control del usuario
    stop_button = tk.Button(app.input_frame, text="Detener Escaneo", command=app.stop_scan)
    stop_button.grid(row=4, column=1, columnspan=1, pady=10) # Lo posiciona junto al botón de inicio
    root.mainloop() # Inicia el bucle de eventos de Tkinter (la ventana se mantiene abierta y responde a interacciones)

""""
Este programa en Python es un escáner de puertos básico que puede identificar puertos abiertos 
en una dirección IP o nombre de host dada. Además, incluye una funcionalidad simulada de 
"analizador de vulnerabilidades" que intentará identificar servicios comunes en puertos conocidos y, 
basándose en esa identificación, sugerir posibles vulnerabilidades o configuraciones inseguras 
(sin explotarlas realmente). Ya integra una GUI para ingresar los datos en una simulación de IDS/IPS.

Vol. 1.1.
Ing. Francisco Daniel Jiménez Cunjamá =)

"""