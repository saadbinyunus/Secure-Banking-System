import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
from datetime import datetime
import socket

class BankServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Bank Server")
        
        # Server control variables
        self.server_running = False
        self.server_thread = None
        self.server_socket = None
        
        # Create main container
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Server control section
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Server Control", padding="10")
        self.control_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        self.btn_start = ttk.Button(self.control_frame, text="Start Server", command=self.start_server)
        self.btn_start.grid(row=0, column=0, padx=5)
        
        self.btn_stop = ttk.Button(self.control_frame, text="Stop Server", command=self.stop_server, state=tk.DISABLED)
        self.btn_stop.grid(row=0, column=1, padx=5)
        
        self.status_label = ttk.Label(self.control_frame, text="Server Status: Stopped")
        self.status_label.grid(row=0, column=2, padx=10)
        
        # Server log display
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Server Activity Log", padding="10")
        self.log_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=15, width=80, state='disabled')
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Audit log display
        self.audit_frame = ttk.LabelFrame(self.main_frame, text="Audit Log", padding="10")
        self.audit_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.audit_text = scrolledtext.ScrolledText(self.audit_frame, height=15, width=80, state='disabled')
        self.audit_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Customer data display
        self.data_frame = ttk.LabelFrame(self.main_frame, text="Customer Data", padding="10")
        self.data_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        self.tree = ttk.Treeview(self.data_frame, columns=('Username', 'Balance', 'Transactions'), show='headings')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Balance', text='Balance')
        self.tree.heading('Transactions', text='Transactions')
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.rowconfigure(1, weight=1)
        self.main_frame.rowconfigure(2, weight=1)
        self.main_frame.rowconfigure(3, weight=1)
        
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        
        self.audit_frame.columnconfigure(0, weight=1)
        self.audit_frame.rowconfigure(0, weight=1)
        
        self.data_frame.columnconfigure(0, weight=1)
        self.data_frame.rowconfigure(0, weight=1)
        
        # Start with empty customer data
        self.update_customer_data()
        
        # Start periodic updates
        self.update_audit_log()
        self.update_customer_data()
        self.periodic_updates()
    
    def log_message(self, message):
        """Add a message to the server log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def update_audit_log(self):
        """Update the audit log display"""
        try:
            with open("audit_decrypt.log", "r") as f:
                content = f.read()
            
            self.audit_text.config(state='normal')
            self.audit_text.delete(1.0, tk.END)
            self.audit_text.insert(tk.END, content)
            self.audit_text.see(tk.END)
            self.audit_text.config(state='disabled')
        except FileNotFoundError:
            self.audit_text.config(state='normal')
            self.audit_text.delete(1.0, tk.END)
            self.audit_text.insert(tk.END, "Audit log not found")
            self.audit_text.config(state='disabled')
    
    def update_customer_data(self):
        """Update the customer data display"""
        # This would normally come from your database
        # For now, we'll use the customers dictionary from the server code
        from bank_server import customers  # Import your actual customers data
        
        # Clear existing data
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add current customer data
        for username, data in customers.items():
            balance = data.get('balance', 0)
            transactions = ', '.join(data.get('transactions', []))
            self.tree.insert('', 'end', values=(username, f"${balance}", transactions))
    
    def periodic_updates(self):
        """Schedule periodic updates of the GUI"""
        self.update_audit_log()
        self.update_customer_data()
        self.root.after(5000, self.periodic_updates)  # Update every 5 seconds
    
    def start_server(self):
        """Start the bank server in a separate thread"""
        if not self.server_running:
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_thread.start()
            self.server_running = True
            self.btn_start.config(state=tk.DISABLED)
            self.btn_stop.config(state=tk.NORMAL)
            self.status_label.config(text="Server Status: Running")
            self.log_message("Server started on localhost:5555")
    
    def run_server(self):
        """Run the server (to be called in a separate thread)"""
        from bank_server import start_server  # Import your actual server function
        start_server()
    
    def stop_server(self):
        """Stop the bank server"""
        if self.server_running:
            try:
                # Create a temporary socket to force the server to exit its accept() call
                temp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                temp_socket.connect(('localhost', 5555))
                temp_socket.close()
                
                self.server_running = False
                self.btn_start.config(state=tk.NORMAL)
                self.btn_stop.config(state=tk.DISABLED)
                self.status_label.config(text="Server Status: Stopped")
                self.log_message("Server stopped")
            except Exception as e:
                self.log_message(f"Error stopping server: {str(e)}")
    
    def on_closing(self):
        """Handle window closing event"""
        if self.server_running:
            if messagebox.askokcancel("Quit", "Server is still running. Are you sure you want to quit?"):
                self.stop_server()
                self.root.destroy()
        else:
            self.root.destroy()

# Create and run the GUI
if __name__ == "__main__":
    root = tk.Tk()
    
    # Import your server code (this is just for the GUI - the actual server code runs separately)
    try:
        import bank_server
    except ImportError:
        pass  # Handle case where server_code isn't available
    
    app = BankServerGUI(root)
    
    # Handle window closing
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    root.mainloop()
    # Close the server socket if it's open