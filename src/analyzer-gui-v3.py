import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import subprocess
import os
import platform
import tempfile

ANALYZER_SCRIPT = "./analyzer.v3"   # your script name

def open_file_crossplatform(path):
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(["xdg-open", path])
        elif system == "Darwin":  # macOS
            subprocess.run(["open", path])
        elif system == "Windows":
            os.startfile(path)
    except Exception as e:
        messagebox.showerror("Open Error", str(e))

def run_analysis():
    file_path = filedialog.askopenfilename(
        filetypes=[("PCAP Files", "*.pcap")]
    )
    if not file_path:
        return

    try:
        # Create temporary report file
        tmp_report = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        tmp_report_path = tmp_report.name
        tmp_report.close()

        # Run the analyzer script and output to file
        result = subprocess.run(
            [ANALYZER_SCRIPT, "-o", tmp_report_path, file_path],
            capture_output=True,
            text=True
        )

        if result.returncode == 0:
            # Open report externally
            open_file_crossplatform(tmp_report_path)

            # Show report inside GUI
            with open(tmp_report_path, "r") as f:
                output_text.delete("1.0", tk.END)
                output_text.insert(tk.END, f.read())

            messagebox.showinfo("Success", "Analysis complete!")
        else:
            messagebox.showerror("Error", result.stderr)

    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Layout
root = tk.Tk()
root.title("PCAP Analyzer GUI")
root.geometry("900x700")

tk.Button(root, text="Select PCAP File and Analyze", command=run_analysis, font=("Arial", 14)).pack(pady=15)

output_text = scrolledtext.ScrolledText(root, width=110, height=35, font=("Consolas", 10))
output_text.pack(padx=10, pady=10)

root.mainloop()
