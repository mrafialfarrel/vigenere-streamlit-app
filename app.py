"""
Vigenere Cipher (26 huruf alfabet) - Streamlit GUI
Jalankan: streamlit run app.py
"""
import os
import struct

import numpy as np
import streamlit as st

MAGIC = b"VGN1"  # penanda header file cipherteks (ikut dienkripsi)


# ---------------------------------------------------------------- Core cipher
def clean_letters(s: str) -> str:
    """Ambil hanya huruf A-Z (ASCII), ubah ke huruf besar."""
    return "".join(c for c in s.upper() if "A" <= c <= "Z")


def vigenere_text(text: str, key: str, decrypt: bool = False) -> str:
    """Vigenere klasik 26 huruf. Input harus sudah berupa A-Z saja."""
    shifts = [ord(c) - 65 for c in key]
    n = len(shifts)
    sign = -1 if decrypt else 1
    return "".join(
        chr((ord(c) - 65 + sign * shifts[i % n]) % 26 + 65)
        for i, c in enumerate(text)
    )


def vigenere_bytes(data: bytes, key: str, decrypt: bool = False) -> bytes:
    """Vigenere untuk byte (mod 256) dengan kunci huruf (A=0..Z=25)."""
    if not data:
        return b""
    arr = np.frombuffer(data, dtype=np.uint8).astype(np.int16)
    ks = np.resize(np.array([ord(c) - 65 for c in key], dtype=np.int16), arr.shape)
    res = (arr - ks) % 256 if decrypt else (arr + ks) % 256
    return res.astype(np.uint8).tobytes()


def group5(s: str) -> str:
    return " ".join(s[i:i + 5] for i in range(0, len(s), 5))


def encrypt_file(data: bytes, filename: str, key: str) -> bytes:
    name = filename.encode("utf-8")
    payload = MAGIC + struct.pack(">H", len(name)) + name + data
    return vigenere_bytes(payload, key)


def decrypt_file(blob: bytes, key: str):
    dec = vigenere_bytes(blob, key, decrypt=True)
    if dec[:4] != MAGIC or len(dec) < 6:
        return None
    (nlen,) = struct.unpack(">H", dec[4:6])
    if len(dec) < 6 + nlen:
        return None
    try:
        name = dec[6:6 + nlen].decode("utf-8")
    except UnicodeDecodeError:
        return None
    return name, dec[6 + nlen:]


# ------------------------------------------------------------------- Styling
CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
html, body, [class*="css"], .stApp { font-family: 'Inter', 'Segoe UI', sans-serif; }
.block-container { padding-top: 2rem; max-width: 1100px; }
#MainMenu, footer { visibility: hidden; }
[data-testid="InputInstructions"] { display: none; }

.hero {
    background: linear-gradient(120deg, #111827 0%, #3b1f2b 55%, #ff4b4b 100%);
    border-radius: 16px; padding: 2rem 2.2rem; margin-bottom: 1.5rem; color: #fff;
}
.hero h1 { margin: 0; font-size: 2rem; font-weight: 700; letter-spacing: -0.5px; color: #fff; }
.hero p { margin: .5rem 0 1rem 0; color: #cbd5e1; font-size: 1rem; }
.tag {
    display: inline-block; padding: 3px 12px; margin-right: 8px; border-radius: 999px;
    background: rgba(255,255,255,.14); border: 1px solid rgba(255,255,255,.25);
    font-size: .78rem; font-weight: 500; color: #e2e8f0;
}

button[data-baseweb="tab"] { font-size: 1rem; font-weight: 600; padding: 10px 22px; }

.step { display: flex; align-items: center; gap: 12px; margin: 1.1rem 0 .5rem 0; }
.step:first-child { margin-top: .2rem; }
.num {
    width: 28px; height: 28px; border-radius: 50%; background: #ff4b4b; color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-size: .85rem; font-weight: 600; flex-shrink: 0;
}
.stitle { font-weight: 600; font-size: 1rem; }
.rtitle { font-weight: 700; font-size: 1.1rem; margin-bottom: .6rem; }

[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 14px; }
[data-testid="stMetric"] {
    background: rgba(255,75,75,.10); border-radius: 10px; padding: 10px 14px;
}
[data-testid="stMetricLabel"] { font-size: .8rem; }
button[kind="primary"], .stDownloadButton button {
    border-radius: 10px; font-weight: 600; padding: .55rem 1.2rem;
}
button[kind="primary"] { background-color: #ff4b4b; border-color: #ff4b4b; color: #fff; }
button[kind="primary"]:hover { background-color: #e03e3e; border-color: #e03e3e; color: #fff; }
[data-baseweb="tab-highlight"] { background-color: #ff4b4b; }
.foot { text-align: center; color: #94a3b8; font-size: .8rem; margin-top: 2rem; }
</style>
"""


def step(n: int, title: str):
    st.markdown(
        f'<div class="step"><div class="num">{n}</div><div class="stitle">{title}</div></div>',
        unsafe_allow_html=True,
    )


# ------------------------------------------------------------------- UI parts
def key_input(prefix: str) -> str:
    c1, c2 = st.columns([4, 1], vertical_alignment="bottom")
    show = c2.checkbox("Tampilkan", key=f"{prefix}_show")
    raw = c1.text_input(
        "Kunci",
        type="default" if show else "password",
        placeholder="contoh: SANDI",
        help="Hanya huruf A-Z yang dipakai. Angka, spasi, dan simbol diabaikan.",
        key=f"{prefix}_key",
    )
    key = clean_letters(raw)
    if raw and not key:
        st.error("Kunci harus berisi minimal satu huruf (A-Z).")
    elif key and key != raw.upper():
        st.caption(f"Kunci yang dipakai: {key}")
    return key


def get_text(prefix: str, label: str, placeholder: str) -> str:
    text = st.text_area(label, height=150, placeholder=placeholder, key=f"{prefix}_txt")
    with st.expander("Atau unggah file .txt"):
        up = st.file_uploader("File .txt", type=["txt"], key=f"{prefix}_txtfile",
                              label_visibility="collapsed")
        if up is not None:
            text = up.getvalue().decode("utf-8", errors="ignore")
            st.caption("Isi file dipakai sebagai masukan, kotak teks di atas diabaikan.")
    return text


def metrics(items):
    cols = st.columns(len(items))
    for col, (label, value) in zip(cols, items):
        col.metric(label, value)


# ------------------------------------------------------------------- Proses
def make_signature(kind, text, up, key, fmt):
    """Ciri masukan saat ini, untuk mendeteksi hasil lama yang sudah tidak sesuai."""
    if kind == "Teks":
        return ("Teks", clean_letters(text), key, fmt)
    return ("File", (up.name, up.size) if up is not None else None, key, fmt)


def process(encrypting, kind, text, up, key, fmt):
    """Jalankan enkripsi/dekripsi, kembalikan dict hasil atau dict error."""
    if not key:
        return {"error": "Kunci belum diisi."}
    if kind == "Teks":
        letters = clean_letters(text)
        if not letters:
            return {"error": "Tidak ada huruf alfabet pada pesan."}
        out = vigenere_text(letters, key, decrypt=not encrypting)
        if encrypting and fmt == "Kelompok 5 huruf":
            out = group5(out)
        return {"mode": "text", "out": out, "n": len(letters), "klen": len(key)}
    if up is None:
        return {"error": "Belum ada file yang dipilih."}
    data = up.getvalue()
    if encrypting:
        out = encrypt_file(data, up.name, key)
        return {"mode": "efile", "out": out, "orig": len(data), "size": len(out),
                "name": up.name}
    result = decrypt_file(data, key)
    if result is None:
        return {"error": "Dekripsi gagal. Kunci salah atau file bukan hasil "
                         "enkripsi dari aplikasi ini."}
    name, plain = result
    return {"mode": "dfile", "out": plain, "name": name}


def show_result(res, encrypting):
    if res["mode"] == "text":
        st.success("Enkripsi berhasil." if encrypting else "Dekripsi berhasil.")
        st.code(res["out"], language=None)
        metrics([("Huruf diproses", f"{res['n']:,}"), ("Panjang kunci", res["klen"])])
        st.write("")
        st.download_button(
            "Simpan cipherteks (.txt)" if encrypting else "Simpan plainteks (.txt)",
            res["out"], file_name="cipherteks.txt" if encrypting else "plainteks.txt",
            mime="text/plain", type="primary", use_container_width=True)
        if encrypting:
            st.caption("Spasi, angka, dan tanda baca tidak ikut dienkripsi.")
    elif res["mode"] == "efile":
        st.success("File berhasil dienkripsi.")
        metrics([("Ukuran asli", f"{res['orig']:,} B"),
                 ("Ukuran hasil", f"{res['size']:,} B")])
        st.write("")
        st.download_button("Simpan cipherteks (.dat)", res["out"],
                           file_name=os.path.splitext(res["name"])[0] + ".dat",
                           mime="application/octet-stream", type="primary",
                           use_container_width=True)
        st.caption(f"Nama file asli ({res['name']}) tersimpan di dalam cipherteks, "
                   "sehingga otomatis dipulihkan saat dekripsi.")
    else:
        st.success("File berhasil didekripsi.")
        metrics([("Nama file", res["name"]), ("Ukuran", f"{len(res['out']):,} B")])
        st.write("")
        st.download_button(f"Simpan {res['name']}", res["out"], file_name=res["name"],
                           mime="application/octet-stream", type="primary",
                           use_container_width=True)


# ------------------------------------------------------------------- Halaman
def render(encrypting: bool):
    p = "enc" if encrypting else "dec"
    label = "Enkripsi" if encrypting else "Dekripsi"
    left, right = st.columns([3, 2], gap="large")

    # ----- kolom kiri: input
    with left:
        with st.container(border=True):
            step(1, "Jenis pesan")
            kind = st.radio("Jenis", ["Teks", "File"], horizontal=True,
                            label_visibility="collapsed", key=f"{p}_kind")

            step(2, "Plainteks" if encrypting else "Cipherteks")
            text, up, fmt = "", None, None
            if kind == "Teks":
                text = get_text(p, "Plainteks" if encrypting else "Cipherteks",
                                "Ketik plainteks di sini" if encrypting
                                else "Tempel cipherteks di sini")
                if encrypting:
                    fmt = st.radio("Format cipherteks", ["Tanpa spasi", "Kelompok 5 huruf"],
                                   horizontal=True, key="enc_fmt")
            else:
                up = st.file_uploader(
                    "Pilih file (teks maupun biner)" if encrypting
                    else "Pilih file cipherteks (.dat)",
                    type=None if encrypting else ["dat"], key=f"{p}_file")

            step(3, "Kunci")
            key = key_input(p)

            st.write("")
            run = st.button(label, type="primary", use_container_width=True,
                            key=f"{p}_run")

    sig = make_signature(kind, text, up, key, fmt)
    if run:
        res = process(encrypting, kind, text, up, key, fmt)
        res["sig"] = sig
        st.session_state[f"{p}_res"] = res

    # ----- kolom kanan: hasil
    with right:
        with st.container(border=True):
            st.markdown('<div class="rtitle">Hasil</div>', unsafe_allow_html=True)
            res = st.session_state.get(f"{p}_res")
            if res is None:
                st.info(f"Isi pesan dan kunci, lalu klik tombol {label}.")
            elif res["sig"] != sig:
                st.warning(f"Masukan sudah berubah. Klik tombol {label} lagi untuk "
                           "memperbarui hasil.")
            elif "error" in res:
                st.error(res["error"])
            else:
                show_result(res, encrypting)


# ------------------------------------------------------------------------- Main
st.set_page_config(page_title="Vigenere Cipher", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)

st.markdown(
    """
    <div class="hero">
        <h1>Vigenere Cipher</h1>
        <p>Enkripsi dan dekripsi pesan teks maupun file dengan kunci pilihan Anda.</p>
        <span class="tag">26 huruf alfabet</span>
        <span class="tag">Teks dan file</span>
        <span class="tag">Kunci bebas panjang</span>
    </div>
    """,
    unsafe_allow_html=True,
)

t1, t2 = st.tabs(["Enkripsi", "Dekripsi"])
with t1:
    render(True)
with t2:
    render(False)

with st.expander("Cara kerja"):
    st.markdown(
        """
- **Teks:** setiap huruf digeser sejauh huruf kunci (A=0 sampai Z=25), kunci diulang
  sepanjang pesan. Rumus: `C = (P + K) mod 26` dan `P = (C - K) mod 26`.
- **File:** seluruh byte dienkripsi dengan `C = (B + K) mod 256` agar file apa pun
  (gambar, docx, dan lainnya) bisa kembali persis sama.
- Jika kunci salah, dekripsi teks menghasilkan huruf acak dan dekripsi file ditolak
  dengan pesan error.
        """
    )
st.markdown('<div class="foot">Program Vigenere Cipher - Tugas Kriptografi</div>',
            unsafe_allow_html=True)
