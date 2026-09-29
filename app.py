"""
Vigenere Cipher (26 huruf alfabet) - Streamlit GUI (versi UI disederhanakan)
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


# ------------------------------------------------------------------- UI parts
def key_input(prefix: str) -> str:
    """Kolom input kunci + tombol lihat/sembunyikan."""
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
        st.caption(f"Kunci yang dipakai: **{key}**")
    return key


def get_text(prefix: str, label: str, placeholder: str) -> str:
    text = st.text_area(label, height=150, placeholder=placeholder, key=f"{prefix}_txt")
    with st.expander("Atau unggah file .txt"):
        up = st.file_uploader("Pilih file .txt", type=["txt"], key=f"{prefix}_txtfile",
                              label_visibility="collapsed")
        if up is not None:
            text = up.getvalue().decode("utf-8", errors="ignore")
            st.caption("Isi file dipakai sebagai masukan, kotak teks di atas diabaikan.")
    return text


def section(number: int, title: str):
    st.markdown(f"#### {number}. {title}")


# ------------------------------------------------------------------- Tab: enkripsi
def tab_encrypt():
    st.write("Ubah plainteks menjadi cipherteks.")
    section(1, "Pilih jenis pesan")
    kind = st.radio("Jenis", ["Teks", "File"], horizontal=True,
                    label_visibility="collapsed", key="enc_kind")

    section(2, "Masukkan plainteks")
    text, up = "", None
    if kind.endswith("Teks"):
        text = get_text("enc", "Plainteks", "Ketik plainteks di sini")
        fmt = st.radio("Format cipherteks", ["Tanpa spasi", "Per 5 huruf"], horizontal=True,
                       key="enc_fmt")
    else:
        up = st.file_uploader("Pilih file (teks maupun biner)",
                              key="enc_file")

    section(3, "Masukkan kunci")
    key = key_input("enc")

    st.divider()
    ready = bool(key) and (bool(clean_letters(text)) if up is None else up is not None)
    if not ready:
        st.info("Isi plainteks dan kunci terlebih dahulu.")
        return

    section(4, "Hasil")
    if up is None:
        ct = vigenere_text(clean_letters(text), key)
        shown = group5(ct) if fmt == "Per 5 huruf" else ct
        st.success("Enkripsi berhasil.")
        st.code(shown, language=None)
        st.caption("Hanya huruf alfabet yang dienkripsi. Spasi, angka, dan tanda baca dibuang.")
        st.download_button("Simpan hasil (.txt)", shown, file_name="cipherteks.txt",
                           mime="text/plain", type="primary")
    else:
        data = up.getvalue()
        out = encrypt_file(data, up.name, key)
        st.success(f"File **{up.name}** ({len(data):,} byte) berhasil dienkripsi.")
        st.download_button("Unduh file cipherteks (.dat)", out,
                           file_name=os.path.splitext(up.name)[0] + ".dat",
                           mime="application/octet-stream", type="primary")
        st.caption("Nama & jenis file asli ikut tersimpan, jadi otomatis kembali "
                   "seperti semula saat didekripsi.")


# ------------------------------------------------------------------- Tab: dekripsi
def tab_decrypt():
    st.write("Kembalikan cipherteks menjadi plainteks. Gunakan kunci yang sama "
             "seperti saat enkripsi.")
    section(1, "Pilih jenis pesan")
    kind = st.radio("Jenis", ["Teks", "File"], horizontal=True,
                    label_visibility="collapsed", key="dec_kind")

    section(2, "Masukkan cipherteks")
    text, up = "", None
    if kind.endswith("Teks"):
        text = get_text("dec", "Cipherteks", "Tempel cipherteks di sini")
    else:
        up = st.file_uploader("Pilih file cipherteks (.dat)", type=["dat"], key="dec_file")

    section(3, "Masukkan kunci")
    key = key_input("dec")

    st.divider()
    ready = bool(key) and (bool(clean_letters(text)) if up is None else up is not None)
    if not ready:
        st.info("Isi cipherteks dan kunci terlebih dahulu.")
        return

    section(4, "Hasil")
    if up is None:
        pt = vigenere_text(clean_letters(text), key, decrypt=True)
        st.success("Dekripsi berhasil.")
        st.code(pt, language=None)
        st.caption("Hasil berupa huruf kapital tanpa spasi.")
        st.download_button("Simpan hasil (.txt)", pt, file_name="plainteks.txt",
                           mime="text/plain", type="primary")
    else:
        result = decrypt_file(up.getvalue(), key)
        if result is None:
            st.error("Dekripsi gagal. Kunci salah atau file bukan hasil enkripsi dari aplikasi ini.")
            return
        name, data = result
        st.success(f"File berhasil didekripsi: **{name}** ({len(data):,} byte)")
        st.download_button(f"Unduh {name}", data, file_name=name,
                           mime="application/octet-stream", type="primary")


# ------------------------------------------------------------------------- Main
st.set_page_config(page_title="Vigenere Cipher", layout="centered")
st.title("Vigenere Cipher")
st.caption("Enkripsi dan dekripsi pesan teks maupun file menggunakan Vigenere Cipher (26 huruf alfabet).")

t1, t2 = st.tabs(["Enkripsi", "Dekripsi"])
with t1:
    tab_encrypt()
with t2:
    tab_decrypt()

with st.expander("Cara kerja"):
    st.markdown(
        """
- **Teks:** setiap huruf digeser sejauh huruf kunci (A=0 ... Z=25), lalu kunci diulang.
  Rumus: `C = (P + K) mod 26` dan `P = (C - K) mod 26`.
- **File:** seluruh byte dienkripsi dengan `C = (B + K) mod 256` agar file apa pun
  (gambar, docx, dan lainnya) bisa kembali persis sama.
- Jika kunci salah, dekripsi teks menghasilkan huruf acak dan dekripsi file ditolak dengan pesan error.
        """
    )
