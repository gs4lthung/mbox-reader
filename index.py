import mailbox
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinterweb import HtmlFrame
from tkcalendar import DateEntry
import bleach
from email.header import decode_header
from datetime import datetime


class MboxViewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("📬 MBOX Viewer - HTML Modes + Encoding Auto-Detect")
        self.geometry("1200x750")
        self.configure(bg="#f0f2f5")

        self.all_emails = []
        self.filtered_emails = []
        self.current_index = None
        self.sort_column = None
        self.sort_reverse = False

        self.allowed_tags = list(bleach.sanitizer.ALLOWED_TAGS) + [
            "p", "br", "hr", "div", "span", "img", "table", "thead", "tbody", "tr", "th", "td"
        ]
        self.allowed_attributes = {
            "*": ["style"],
            "a": ["href", "title"],
            "img": ["src", "alt", "width", "height"],
        }

        self.style_ui()
        self.create_widgets()

    def style_ui(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=28,
                        background="#ffffff", fieldbackground="#ffffff")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"),
                        background="#e0e0e0")
        style.map("Treeview", background=[("selected", "#d0e0ff")])

    def create_widgets(self):
        top_frame = ttk.Frame(self)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Button(top_frame, text="📂 Load MBOX", command=self.load_mbox).pack(side=tk.LEFT)
        ttk.Label(top_frame, text="🔍 Search:").pack(side=tk.LEFT, padx=(10, 5))

        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<Return>", lambda e: self.apply_filters())

        ttk.Button(top_frame, text="Go", command=self.apply_filters).pack(side=tk.LEFT, padx=3)
        ttk.Button(top_frame, text="Clear", command=self.clear_filters).pack(side=tk.LEFT)

        ttk.Label(top_frame, text="📨 Sender:").pack(side=tk.LEFT, padx=(20, 5))
        self.sender_var = tk.StringVar()
        self.sender_combo = ttk.Combobox(top_frame, textvariable=self.sender_var, state="readonly", width=25)
        self.sender_combo.pack(side=tk.LEFT)
        self.sender_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filters())

        ttk.Label(top_frame, text="📅 Before:").pack(side=tk.LEFT, padx=(15, 5))
        self.date_entry = DateEntry(top_frame, width=12, background='darkblue',
                                    foreground='white', borderwidth=2, date_pattern='yyyy-mm-dd')
        self.date_entry.pack(side=tk.LEFT)
        self.date_entry.bind("<<DateEntrySelected>>", lambda e: self.apply_filters())

        paned = ttk.PanedWindow(self, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # TreeView setup
        self.tree = ttk.Treeview(self, columns=("From", "Subject", "Date"), show="headings")
        for col in ("From", "Subject", "Date"):
            self.tree.heading(col, text=col, command=lambda c=col.lower(): self.sort_by_column(c))
            self.tree.column(col, anchor=tk.W, width=300, minwidth=150, stretch=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_email_body)
        tree_scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        tree_frame = ttk.Frame(paned)
        self.tree.pack(in_=tree_frame, side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(in_=tree_frame, side=tk.RIGHT, fill=tk.Y)
        paned.add(tree_frame, weight=1)

        # Email preview frame
        preview_frame = ttk.Frame(paned)
        preview_controls = ttk.Frame(preview_frame)
        preview_controls.pack(anchor="w", padx=10, pady=5)

        self.toggle_btn = ttk.Button(preview_controls, text="👁 Toggle HTML", command=self.toggle_html_mode)
        self.toggle_btn.pack(side=tk.LEFT)

        ttk.Label(preview_controls, text="Render Mode:").pack(side=tk.LEFT, padx=10)
        self.render_mode_var = tk.StringVar(value="sanitized")
        self.render_mode_dropdown = ttk.Combobox(
            preview_controls, textvariable=self.render_mode_var,
            values=["plaintext", "sanitized", "raw"], width=15, state="readonly"
        )
        self.render_mode_dropdown.pack(side=tk.LEFT)
        self.render_mode_dropdown.bind("<<ComboboxSelected>>", lambda e: self.show_email_body(None))

        self.html_view = HtmlFrame(preview_frame, horizontal_scrollbar="auto")
        self.html_view.pack(fill=tk.BOTH, expand=True)
        paned.add(preview_frame, weight=2)

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
            self.populate_senders()
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def populate_senders(self):
        unique_senders = sorted(set(e["from"] for e in self.all_emails))
        self.sender_combo["values"] = ["(Any)"] + unique_senders
        self.sender_combo.set("(Any)")

    def refresh_table(self):
        self.tree.delete(*self.tree.get_children())
        for i, email in enumerate(self.filtered_emails):
            self.tree.insert("", "end", iid=str(i),
                             values=(email["from"], email["subject"], email["date"]))

    def toggle_html_mode(self):
        current = self.render_mode_var.get()
        if current == "plaintext":
            self.render_mode_var.set("sanitized")
        elif current == "sanitized":
            self.render_mode_var.set("raw")
        else:
            self.render_mode_var.set("plaintext")
        self.show_email_body(None)

    def decode_payload(self, part):
        try:
            charset = part.get_content_charset()
            payload = part.get_payload(decode=True)
            if payload:
                if charset:
                    return payload.decode(charset, errors="replace")
                return payload.decode("utf-8", errors="replace")
        except Exception:
            return ""
        return ""

    def show_email_body(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        self.current_index = index
        message = self.filtered_emails[index]["message"]

        sender = message.get("from", "N/A")
        subject = message.get("subject", "No Subject")
        date = message.get("date", "No Date")

        html_body = None
        plain_body = ""

        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                if content_type == "text/html" and html_body is None:
                    html_body = self.decode_payload(part)
                elif content_type == "text/plain" and not plain_body:
                    plain_body = self.decode_payload(part)
        else:
            content_type = message.get_content_type()
            if content_type == "text/html":
                html_body = self.decode_payload(message)
            else:
                plain_body = self.decode_payload(message)

        mode = self.render_mode_var.get()

        if mode == "raw" and html_body:
            content = f"""
                <div style="font-family:Segoe UI;">
                    <p><b>From:</b> {sender}<br><b>Subject:</b> {subject}<br><b>Date:</b> {date}</p>
                    <hr>
                    {html_body}
                </div>
            """
        elif mode == "sanitized" and html_body:
            safe_html = bleach.clean(
                html_body,
                tags=self.allowed_tags,
                attributes=self.allowed_attributes,
                strip=True
            )
            content = f"""
                <div style="font-family:Segoe UI;">
                    <p><b>From:</b> {sender}<br><b>Subject:</b> {subject}<br><b>Date:</b> {date}</p>
                    <hr>
                    {safe_html}
                </div>
            """
        else:
            if not plain_body:
                plain_body = "[No plain text content available]"
            content = f"""
                <div style="font-family:Segoe UI;">
                    <p><b>From:</b> {sender}<br><b>Subject:</b> {subject}<br><b>Date:</b> {date}</p>
                    <hr>
                    <pre style="white-space: pre-wrap; font-family: Consolas, monospace;">{plain_body}</pre>
                </div>
            """

        self.html_view.load_html(content)

    def apply_filters(self):
        query = self.search_var.get().strip().lower()
        selected_sender = self.sender_var.get()
        before_date = self.date_entry.get_date()
        self.filtered_emails = []

        for e in self.all_emails:
            msg = e["message"]

            # Query Match
            if query:
                meta = f"{e['from']} {e['subject']} {e['date']}".lower()
                if query in meta:
                    match_found = True
                else:
                    body = ""
                    try:
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/plain":
                                    body += self.decode_payload(part)
                        else:
                            body += self.decode_payload(msg)
                    except Exception:
                        pass
                    match_found = query in body.lower()

                if not match_found:
                    continue

            # Sender filter
            if selected_sender != "(Any)" and e["from"] != selected_sender:
                continue

            # Date filter
            try:
                msg_date = datetime.strptime(e["date"][:25], "%a, %d %b %Y %H:%M:%S")
                if msg_date.date() > before_date:
                    continue
            except:
                pass

            self.filtered_emails.append(e)

        self.refresh_table()

    def clear_filters(self):
        self.search_var.set("")
        self.sender_combo.set("(Any)")
        self.date_entry.set_date(datetime.today())
        self.filtered_emails = list(self.all_emails)
        self.refresh_table()

    def sort_by_column(self, key):
        col_map = {"from": "From", "subject": "Subject", "date": "Date"}
        if self.sort_column == key:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = key
            self.sort_reverse = False

        self.filtered_emails.sort(
            key=lambda e: (e.get(key) or "").lower(),
            reverse=self.sort_reverse
        )
        self.refresh_table()

        for col in col_map:
            heading = col_map[col]
            if col == key:
                heading += " 🔽" if self.sort_reverse else " 🔼"
            self.tree.heading(col_map[col], text=heading,
                              command=lambda c=col: self.sort_by_column(c))


if __name__ == "__main__":
    app = MboxViewer()
    app.mainloop()
