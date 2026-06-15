import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import scapy.all as scapy

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NexusCapture - Advanced Protocol Analyzer")
        self.root.geometry("1000x750")
        
        # Threat management state
        self.packet_queue = queue.Queue()
        self.sniffing = False
        self.packet_list = []
        self.sniff_thread = None
        
        self._setup_styles()
        self._build_ui()
        self._start_queue_listener()

    def _setup_styles(self):
        """Initializes a dark, modern interface style."""
        self.style = ttk.Style(self.root) 
        self.style.theme_use("clam")
        
        # Configure a dark palette
        self.style.configure(".", background="#1e1e24", foreground="#f5f5f5")
        self.style.configure("Treeview", background="#2a2a35", fieldbackground="#2a2a35", foreground="#f5f5f5", rowheight=26)
        self.style.map("Treeview", background=[("selected", "#4a4ae0")])
        self.style.configure("TButton", background="#3a3a4a", foreground="#f5f5f5", borderwidth=0, padding=6)
        self.style.map("TButton", background=[("active", "#4a4ae0"), ("disabled", "#2a2a35")])
        self.style.configure("TLabel", background="#1e1e24", foreground="#c5c5d5")

    def _build_ui(self):
        """Constructs the application layout."""
        # Top Control Panel
        control_frame = ttk.Frame(self.root, padding=10)
        control_frame.pack(fill=tk.X)
        
        # --- Row 1: Action Buttons ---
        action_frame = ttk.Frame(control_frame)
        action_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.start_btn = ttk.Button(action_frame, text="▶ Start Sniffing", command=self.start_sniffing)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(action_frame, text="■ Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(action_frame, text="🗑 Clear Live Feed", command=self.clear_packets)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        self.save_btn = ttk.Button(action_frame, text="💾 Save to PCAP", command=self.save_pcap)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        self.status_label = ttk.Label(action_frame, text="Status: Idle", font=("Helvetica", 10, "italic"))
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # --- Row 2: BPF Filter Bar ---
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill=tk.X)
        
        ttk.Label(filter_frame, text="Capture Filter (BPF):").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(filter_frame, textvariable=self.filter_var, width=60, bg="#2a2a35", fg="#f5f5f5", insertbackground="white", borderwidth=1, relief="solid")
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(filter_frame, text="(e.g., 'icmp', 'tcp port 80', 'host 8.8.8.8')", foreground="#777788").pack(side=tk.LEFT)

        # Main Display Area (Packet List View)
        table_frame = ttk.Frame(self.root, padding=10)
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("id", "time", "src_ip", "dst_ip", "protocol", "length")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        
        self.tree.heading("id", text="ID")
        self.tree.heading("time", text="Time Offset")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("length", text="Length (Bytes)")
        
        self.tree.column("id", width=50, anchor=tk.CENTER)
        self.tree.column("time", width=100, anchor=tk.CENTER)
        self.tree.column("src_ip", width=150)
        self.tree.column("dst_ip", width=150)
        self.tree.column("protocol", width=100, anchor=tk.CENTER)
        self.tree.column("length", width=100, anchor=tk.E) 
        
        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_selected)

        # Bottom Inspector Panel (Deep Packet Details)
        inspector_frame = ttk.Frame(self.root, padding=10)
        inspector_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(inspector_frame, text="Deep Packet Inspection Panel", font=("Helvetica", 11, "bold")).pack(anchor=tk.W)
        
        self.inspector_text = tk.Text(inspector_frame, bg="#15151a", fg="#a5efad", insertbackground="white", font=("Courier New", 10))
        self.inspector_text.pack(fill=tk.BOTH, expand=True, pady=5)

    def _packet_callback(self, packet):
        """Asynchronous callback executed by Scapy for every packet intercepted."""
        if self.sniffing:
            self.packet_queue.put(packet)

    def _sniff_worker(self, filter_string):
        """The core capture loop executed inside a dedicated background thread."""
        try:
            if filter_string.strip():
                # Run with BPF Filter
                scapy.sniff(prn=self._packet_callback, store=0, stop_filter=lambda p: not self.sniffing, filter=filter_string)
            else:
                # Run without Filter
                scapy.sniff(prn=self._packet_callback, store=0, stop_filter=lambda p: not self.sniffing)
        except Exception as e:
            self.sniffing = False
            self.root.after(0, lambda: self._handle_sniff_error(e))

    def _handle_sniff_error(self, error_msg):
        """Safely resets the UI if the background thread crashes (e.g., bad filter syntax)."""
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.filter_entry.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Error / Stopped")
        messagebox.showerror("Capture Error", f"Failed to start packet capture.\n(If you used a filter, check for typos!).\n\nDetails:\n{error_msg}")

    def _start_queue_listener(self):
        """Regularly checks the communication queue for incoming packets to render."""
        while not self.packet_queue.empty():
            packet = self.packet_queue.get()
            self.packet_list.append(packet)
            self._render_packet_to_ui(packet)
            
        self.root.after(100, self._start_queue_listener)

    def _render_packet_to_ui(self, packet):
        """Parses network protocol details and updates the Treeview."""
        pkt_id = len(self.packet_list)
        time_str = f"+{pkt_id * 0.1:.2f}s" 
        
        src_ip, dst_ip, proto = "N/A", "N/A", "RAW"
        
        if packet.haslayer(scapy.IP):
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            proto = "IP"
            
            if packet.haslayer(scapy.TCP):
                proto = "TCP"
            elif packet.haslayer(scapy.UDP):
                proto = "UDP"
            elif packet.haslayer(scapy.ICMP):
                proto = "ICMP"
                
        elif packet.haslayer(scapy.ARP):
            src_ip = packet[scapy.ARP].psrc
            dst_ip = packet[scapy.ARP].pdst
            proto = "ARP"

        pkt_len = len(packet)
        self.tree.insert("", tk.END, values=(pkt_id, time_str, src_ip, dst_ip, proto, pkt_len))

    def on_packet_selected(self, event):
        """Triggered when a user clicks on a packet in the table."""
        selected_item = self.tree.selection()
        if not selected_item:
            return
            
        item_values = self.tree.item(selected_item[0], "values")
        pkt_id = int(item_values[0]) - 1
        
        target_packet = self.packet_list[pkt_id]
        
        self.inspector_text.delete("1.0", tk.END)
        self.inspector_text.insert(tk.END, f"=== PACKET LAYER DIAGNOSTIC LOG ===\n\n")
        self.inspector_text.insert(tk.END, target_packet.show(dump=True))
        
        if target_packet.haslayer(scapy.Raw):
            payload = target_packet[scapy.Raw].load
            self.inspector_text.insert(tk.END, f"\n=== APPLICATION PAYLOAD DATA ===\n")
            self.inspector_text.insert(tk.END, f"Raw Bytes: {payload}\n")
            self.inspector_text.insert(tk.END, f"Clean String Decode: {payload.decode('utf-8', errors='ignore')}\n")

    def start_sniffing(self):
        """Toggles the state machine to run state."""
        self.sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.filter_entry.config(state=tk.DISABLED) # Lock filter box while running
        self.status_label.config(text="Status: Active Capture Loop Running...")
        
        # Grab the filter text before starting the thread
        current_filter = self.filter_var.get()
        
        self.sniff_thread = threading.Thread(target=self._sniff_worker, args=(current_filter,), daemon=True)
        self.sniff_thread.start()

    def stop_sniffing(self):
        """Gracefully signs off packet intercept structures."""
        self.sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.filter_entry.config(state=tk.NORMAL) # Unlock filter box
        self.status_label.config(text="Status: Sniffing Terminated Safely.")

    def clear_packets(self):
        """Resets application database layers."""
        self.tree.delete(*self.tree.get_children())
        self.packet_list.clear()
        self.inspector_text.delete("1.0", tk.END)

    def save_pcap(self):
        """Exports captured packets to a standard Wireshark PCAP file."""
        if not self.packet_list:
            messagebox.showwarning("Empty Capture", "There are no packets currently captured to save.")
            return
            
        filepath = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")],
            title="Save Network Capture"
        )
        
        if filepath:
            try:
                scapy.wrpcap(filepath, self.packet_list)
                messagebox.showinfo("Export Successful", f"Saved {len(self.packet_list)} packets successfully to:\n{filepath}")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to save PCAP file:\n{e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
