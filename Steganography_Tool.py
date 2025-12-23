import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from PIL import Image

# Optional drag-and-drop
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
except ImportError:
    TkinterDnD = None
    DND_FILES = None

# ---- CONFIG: how many LSB bits per color channel we use ----
BITS_PER_CHANNEL = 3  # 3-LSB high-capacity mode


# ---------- Core helper functions ----------

def bytes_to_bits(data: bytes):
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits):
    if len(bits) % 8 != 0:
        raise ValueError("Bits length must be multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def xor_bytes(data: bytes, password: str) -> bytes:
    """Simple XOR encryption/decryption."""
    if not password:
        return data
    key = password.encode("utf-8")
    key_len = len(key)
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % key_len])
    return bytes(out)


def calc_capacity(img: Image.Image) -> int:
    """Return capacity in BYTES using BITS_PER_CHANNEL LSBs per RGB channel."""
    width, height = img.size
    total_bits = width * height * 3 * BITS_PER_CHANNEL
    return total_bits // 8  # bytes


def embed_payload_in_image(cover_path: str, out_path: str, payload: bytes):
    img = Image.open(cover_path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    max_bytes = calc_capacity(img)
    if len(payload) > max_bytes:
        payload_mb = len(payload) / (1024 * 1024)
        max_mb = max_bytes / (1024 * 1024)
        raise ValueError(
            "Payload too large for this image.\n\n"
            f"Your data size : {payload_mb:.2f} MB ({len(payload)} bytes)\n"
            f"Image capacity : {max_mb:.2f} MB ({max_bytes} bytes)\n\n"
            f"Using {BITS_PER_CHANNEL} LSBs per color channel.\n\n"
            "Solution:\n"
            "• Use a larger resolution image (more pixels), or\n"
            "• Compress the file (e.g., ZIP), or\n"
            "• Hide a smaller amount of data."
        )

    bits = bytes_to_bits(payload)

    pixels = list(img.getdata())
    flat_channels = []
    for r, g, b in pixels:
        flat_channels.extend([r, g, b])

    # Each channel can store BITS_PER_CHANNEL bits
    if len(bits) > len(flat_channels) * BITS_PER_CHANNEL:
        raise ValueError("Not enough pixels to store all bits (after LSB expansion).")

    mask_clear = ~((1 << BITS_PER_CHANNEL) - 1)  # clear last k bits
    bit_index = 0

    for i in range(len(flat_channels)):
        if bit_index >= len(bits):
            break

        # Collect up to BITS_PER_CHANNEL bits for this channel
        group_bits = []
        for _ in range(BITS_PER_CHANNEL):
            if bit_index < len(bits):
                group_bits.append(bits[bit_index])
                bit_index += 1
            else:
                group_bits.append(0)  # pad with zero if bits finished

        # Convert group bits to value
        group_val = 0
        for b in group_bits:
            group_val = (group_val << 1) | b

        # Clear last BITS_PER_CHANNEL bits and set new ones
        orig = flat_channels[i]
        flat_channels[i] = (orig & mask_clear) | group_val

    # rebuild pixels
    new_pixels = []
    it = iter(flat_channels)
    for _ in range(len(pixels)):
        r = next(it)
        g = next(it)
        b = next(it)
        new_pixels.append((r, g, b))

    stego_img = Image.new("RGB", img.size)
    stego_img.putdata(new_pixels)
    stego_img.save(out_path)


def extract_payload_from_image(stego_path: str) -> bytes:
    img = Image.open(stego_path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    pixels = list(img.getdata())
    bits = []
    mask_group = (1 << BITS_PER_CHANNEL) - 1

    # Read BITS_PER_CHANNEL bits from each channel
    for r, g, b in pixels:
        for channel in (r, g, b):
            group_val = channel & mask_group
            # Convert group_val to bits (MSB first inside the group)
            for shift in range(BITS_PER_CHANNEL - 1, -1, -1):
                bits.append((group_val >> shift) & 1)

    # 1 byte type + 4 bytes length = 5 bytes = 40 bits
    header_bits = bits[:40]
    header_bytes = bits_to_bytes(header_bits)
    data_type = header_bytes[0:1]  # b'T' or b'F'
    length = int.from_bytes(header_bytes[1:5], "big")

    total_bits_needed = 40 + length * 8
    if total_bits_needed > len(bits):
        raise ValueError("Image does not contain full payload or is corrupted.")

    data_bits = bits[40:total_bits_needed]
    data_bytes = bits_to_bytes(data_bits)
    return data_type + length.to_bytes(4, "big") + data_bytes


# ---------- GUI class ----------

class StegCLIGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography GUI Tool (Text/File Hiding) by Vatsal Gajjar")
        self.root.geometry("780x600")

        self.data_mode = tk.StringVar(value="text")

        # drag-and-drop available?
        self.has_dnd = TkinterDnD is not None and DND_FILES is not None

        self.build_ui()

    def build_ui(self):
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.embed_frame = ttk.Frame(notebook)
        self.extract_frame = ttk.Frame(notebook)

        notebook.add(self.embed_frame, text="Embed")
        notebook.add(self.extract_frame, text="Extract")

        self.build_embed_tab()
        self.build_extract_tab()

    # ---------- EMBED TAB ----------

    def build_embed_tab(self):
        frame = self.embed_frame

        # Mode (text/file)
        mode_frame = ttk.LabelFrame(frame, text=f"Data Type (Using LSBs)")
        mode_frame.pack(fill="x", padx=10, pady=5)
        ttk.Radiobutton(
            mode_frame, text="Text", value="text", variable=self.data_mode,
            command=self.update_mode
        ).pack(side="left", padx=5, pady=5)
        ttk.Radiobutton(
            mode_frame, text="File", value="file", variable=self.data_mode,
            command=self.update_mode
        ).pack(side="left", padx=5, pady=5)

        # Text secret
        self.text_group = ttk.LabelFrame(frame, text="Secret Text")
        self.text_group.pack(fill="both", padx=10, pady=5, expand=True)
        self.text_widget = tk.Text(self.text_group, height=6)
        self.text_widget.pack(fill="both", expand=True, padx=5, pady=5)

        # File secret
        self.file_group = ttk.LabelFrame(frame, text="Secret File (you can use .zip)")
        self.file_path_var = tk.StringVar()
        file_inner = ttk.Frame(self.file_group)
        file_inner.pack(fill="x", padx=5, pady=5)
        ttk.Entry(file_inner, textvariable=self.file_path_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(file_inner, text="Browse", command=self.browse_secret_file).pack(
            side="left", padx=5
        )

        # Cover image
        img_frame = ttk.LabelFrame(frame, text="Cover Image (PNG/BMP)")
        img_frame.pack(fill="x", padx=10, pady=5)
        self.cover_path_var = tk.StringVar()
        img_inner = ttk.Frame(img_frame)
        img_inner.pack(fill="x", padx=5, pady=5)
        ttk.Entry(img_inner, textvariable=self.cover_path_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(img_inner, text="Browse", command=self.browse_cover_image).pack(
            side="left", padx=5
        )

        # Drag & Drop label for stego image (BIGGER BOX)
        dnd_text = "Drag & Drop stego image here"
        if not self.has_dnd:
            dnd_text += " (tkinterdnd2 not installed)"

        self.extract_dnd_label = tk.Label(
            img_frame,
            text=dnd_text,
            relief="ridge",
            bd=2,
            anchor="center",
            height=5,        
            font=("Segoe UI", 10)
        )
        self.extract_dnd_label.pack(fill="both", expand=True, padx=5, pady=8, ipady=10)

        # Password
        enc_frame = ttk.LabelFrame(frame, text="Encryption (Optional - XOR)")
        enc_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(enc_frame, text="Password:").pack(side="left", padx=5)
        self.enc_password_var = tk.StringVar()
        ttk.Entry(enc_frame, textvariable=self.enc_password_var, show="*").pack(
            side="left", fill="x", expand=True, padx=5
        )

        # Button
        ttk.Button(frame, text="Embed Data into Image", command=self.do_embed).pack(
            pady=10
        )

        self.update_mode()

    # ---------- EXTRACT TAB ----------

    def build_extract_tab(self):
        frame = self.extract_frame

        # Stego image
        img_frame = ttk.LabelFrame(frame, text="Stego Image (with hidden data)")
        img_frame.pack(fill="x", padx=10, pady=5)
        self.stego_path_var = tk.StringVar()
        img_inner = ttk.Frame(img_frame)
        img_inner.pack(fill="x", padx=5, pady=5)
        ttk.Entry(img_inner, textvariable=self.stego_path_var).pack(
            side="left", fill="x", expand=True
        )
        ttk.Button(img_inner, text="Browse", command=self.browse_stego_image).pack(
            side="left", padx=5
        )

        # Drag & Drop label for stego image (BIGGER BOX)
        dnd_text = "Drag & Drop stego image here"
        if not self.has_dnd:
            dnd_text += " (tkinterdnd2 not installed)"

        self.extract_dnd_label = tk.Label(
            img_frame,
            text=dnd_text,
            relief="ridge",
            bd=2,
            anchor="center",
            height=5,          
            font=("Segoe UI", 10)
        )
        self.extract_dnd_label.pack(fill="both", expand=True, padx=5, pady=8, ipady=10)

        # Password
        enc_frame = ttk.LabelFrame(frame, text="Decryption (if password used)")
        enc_frame.pack(fill="x", padx=10, pady=5)
        ttk.Label(enc_frame, text="Password:").pack(side="left", padx=5)
        self.dec_password_var = tk.StringVar()
        ttk.Entry(enc_frame, textvariable=self.dec_password_var, show="*").pack(
            side="left", fill="x", expand=True, padx=5
        )

        # Output text
        out_frame = ttk.LabelFrame(frame, text="Extracted Text (if any)")
        out_frame.pack(fill="both", padx=10, pady=5, expand=True)
        self.output_text = tk.Text(out_frame, height=8)
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Button
        ttk.Button(frame, text="Extract Data", command=self.do_extract).pack(pady=10)

    # ---------- DnD Callbacks ----------

    def on_embed_image_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            self.cover_path_var.set(files[0])

    def on_extract_image_drop(self, event):
        files = self.root.tk.splitlist(event.data)
        if files:
            self.stego_path_var.set(files[0])

    # ---------- Helper UI methods ----------

    def update_mode(self):
        """Show/hide text/file groups."""
        if self.data_mode.get() == "text":
            self.text_group.pack(fill="both", padx=10, pady=5, expand=True)
            self.file_group.pack_forget()
        else:
            self.text_group.pack_forget()
            self.file_group.pack(fill="x", padx=10, pady=5)

    def browse_secret_file(self):
        path = filedialog.askopenfilename(title="Select file to hide")
        if path:
            self.file_path_var.set(path)

    def browse_cover_image(self):
        path = filedialog.askopenfilename(
            title="Select cover image",
            filetypes=[("Images", "*.png *.bmp *.PNG *.BMP"), ("All files", "*.*")]
        )
        if path:
            self.cover_path_var.set(path)

    def browse_stego_image(self):
        path = filedialog.askopenfilename(
            title="Select stego image",
            filetypes=[("Images", "*.png *.bmp *.PNG *.BMP"), ("All files", "*.*")]
        )
        if path:
            self.stego_path_var.set(path)

    # ---------- Core actions ----------

    def do_embed(self):
        cover = self.cover_path_var.get().strip()
        if not cover:
            messagebox.showerror("Error", "Please select a cover image.")
            return

        mode = self.data_mode.get()
        password = self.enc_password_var.get().strip()

        if mode == "text":
            msg = self.text_widget.get("1.0", "end").strip()
            if not msg:
                messagebox.showerror("Error", "Secret text is empty.")
                return
            data = msg.encode("utf-8")
            data_type = b"T"
        else:
            file_path = self.file_path_var.get().strip()
            if not file_path:
                messagebox.showerror("Error", "Please select a file to hide.")
                return
            p = Path(file_path)
            if not p.is_file():
                messagebox.showerror("Error", f"File not found: {file_path}")
                return
            data = p.read_bytes()
            data_type = b"F"

        data = xor_bytes(data, password)
        length_bytes = len(data).to_bytes(4, "big")
        payload = data_type + length_bytes + data

        out_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png")],
            title="Save stego image as"
        )
        if not out_path:
            return

        try:
            embed_payload_in_image(cover, out_path, payload)
        except Exception as e:
            messagebox.showerror("Error", f"Embedding failed: {e}")
            return

        messagebox.showinfo("Success", f"Data embedded successfully!\nSaved as:\n{out_path}")

    def do_extract(self):
        stego = self.stego_path_var.get().strip()
        if not stego:
            messagebox.showerror("Error", "Please select a stego image.")
            return

        try:
            payload = extract_payload_from_image(stego)
        except Exception as e:
            messagebox.showerror("Error", f"Extraction failed: {e}")
            return

        data_type = payload[0:1]
        length = int.from_bytes(payload[1:5], "big")
        data = payload[5: 5 + length]

        password = self.dec_password_var.get().strip()
        data = xor_bytes(data, password)

        if data_type == b"T":
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                text = "<Could not decode text>"
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", text)
            messagebox.showinfo("Info", "Extracted TEXT. Shown in the text box.")
        elif data_type == b"F":
            save_path = filedialog.asksaveasfilename(
                title="Save extracted file as ZIP",
                defaultextension=".zip",
                initialfile="secret.zip",
                filetypes=[("ZIP archive", "*.zip"), ("All files", "*.*")]
            )
            if not save_path:
                return
            try:
                Path(save_path).write_bytes(data)
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file: {e}")
                return
            messagebox.showinfo("Success", f"File extracted and saved as:\n{save_path}")
        else:
            messagebox.showerror("Error", "Unknown data type in payload.")


def main():
    # Use TkinterDnD.Tk if available, else normal tk.Tk
    if TkinterDnD is not None:
        root = TkinterDnD.Tk()
    else:
        root = tk.Tk()
    app = StegCLIGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
