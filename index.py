import mailbox
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

class MboxViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("📬 MBOX Email Viewer")
        self.geometry("1100x700")
        self.configure(bg="#f0f2f5")

        self.all_emails = []
        self.filtered_emails = []
        self.sort_column = None
        self.sort_reverse = False

        self.style_ui()
        self.create_widgets()

    def style_ui(self):
        style = ttk.Style(self)
        self.tk.call("source", "azure.tcl")  # Optional if using ttk themes
        style.theme_use("default")

        style.configure("Treeview",
                        font=("Segoe UI", 10),
                        rowheight=28,
                        background="#ffffff",
                        fieldbackground="#ffffff")
        style.configure("Treeview.Heading",
                        font=("Segoe UI", 10, "bold"),
                        background="#e0e0e0")
        style.map("Treeview", background=[("selected", "#d0e0ff")])

    def create_widgets(self):
        # Top bar with load/search
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(top_frame, text="📂 Load MBOX", command=self.load_mbox).pack(side=tk.LEFT)

        ttk.Label(top_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=(20, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<Return>", lambda e: self.apply_search())

        ttk.Button(top_frame, text="Go", command=self.apply_search).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Clear", command=self.clear_search).pack(side=tk.LEFT)

        # Split view
        paned = ttk.PanedWindow(self, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Treeview for email summary
        self.tree = ttk.Treeview(self, columns=("From", "Subject", "Date"), show="headings")
        self.tree.heading("From", text="From", command=lambda: self.sort_by_column("from"))
        self.tree.heading("Subject", text="Subject", command=lambda: self.sort_by_column("subject"))
        self.tree.heading("Date", text="Date", command=lambda: self.sort_by_column("date"))

        for col in ("From", "Subject", "Date"):
            self.tree.column(col, anchor=tk.W, width=300, minwidth=150, stretch=True)

        self.tree.bind("<<TreeviewSelect>>", self.show_email_body)

        tree_scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        tree_frame = ttk.Frame(paned)
        self.tree.pack(in_=tree_frame, side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(in_=tree_frame, side=tk.RIGHT, fill=tk.Y)

        paned.add(tree_frame, weight=1)

        # Email body view
        body_frame = ttk.Frame(paned)
        self.text_area = tk.Text(body_frame, wrap=tk.WORD, font=("Segoe UI", 10), bg="#fefefe")
        self.text_area.pack(fill=tk.BOTH, expand=True)

        paned.add(body_frame, weight=2)

    def load_mbox(self):
        path = filedialog.askopenfilename(filetypes=[("MBOX files", "*.mbox")])
        if not path:
            return

        self.tree.delete(*self.tree.get_children())
        self.all_emails.clear()

        try:
            mbox = mailbox.mbox(path)
            for message in mbox:
                self.all_emails.append({
                    "from": message.get("from", "N/A"),
                    "subject": message.get("subject", "No subject"),
                    "date": message.get("date", "No date"),
                    "message": message
                })
            self.filtered_emails = list(self.all_emails)
            self.refresh_table()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for i, email in enumerate(self.filtered_emails):
            self.tree.insert("", "end", iid=str(i),
                             values=(email["from"], email["subject"], email["date"]))

    def show_email_body(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        message = self.filtered_emails[index]["message"]

        body = ""
        if message.is_multipart():
            for part in message.walk():
                if part.get_content_type() == "text/plain":
                    body = part.get_payload(decode=True).decode(errors="ignore")
                    break
        else:
            body = message.get_payload(decode=True).decode(errors="ignore")

        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, body)

    def apply_search(self):
        query = self.search_var.get().strip().lower()
        self.filtered_emails = [
            e for e in self.all_emails
            if query in e["from"].lower()
            or query in e["subject"].lower()
            or query in e["date"].lower()
        ]
        self.refresh_table()

    def clear_search(self):
        self.search_var.set("")
        self.filtered_emails = list(self.all_emails)
        self.refresh_table()

    def sort_by_column(self, key):
        if self.sort_column == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = key
            self.sort_reverse = False

        self.filtered_emails.sort(
            key=lambda e: e[key].lower() if isinstance(e[key], str) else e[key],
            reverse=self.sort_reverse
        )
        self.refresh_table()

if __name__ == "__main__":
    app = MboxViewer()
    app.mainloop()
