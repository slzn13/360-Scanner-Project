import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import os

def run_analysis():
    file_path = filedialog.askopenfilename(filetypes=[("PCAP Files", "*.pcap")])
    if not file_path:
        return
    try:
        result = subprocess.run(["./pcap_scanner.sh", file_path], capture_output=True, text=True)
        if result.returncode == 0:
            pdf_path = os.path.join("report", "report.pdf")
            subprocess.run(["xdg-open", pdf_path])  # Or use 'open' on macOS, 'start' on Windows
            messagebox.showinfo("Success", "Analysis complete! Report opened.")
        else:
            messagebox.showerror("Error", result.stderr)
    except Exception as e:
        messagebox.showerror("Error", str(e))

root = tk.Tk()
root.title("PCAP Scanner GUI")
tk.Button(root, text="Select PCAP File and Analyze", command=run_analysis).pack(pady=20)
root.mainloop()
