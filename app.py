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
    """
    Vigenere untuk byte (mod 256) memakai kunci huruf (A=0..Z=25).
    Dipakai untuk file sembarang karena seluruh byte harus bisa dienkripsi
    dan dikembalikan persis sama.
    """
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


# ------------------------------------------------------------------------- UI
st.set_page_config(page_title="Vigenere Cipher", page_icon="🔐", layout="centered")
st.title("🔐 Vigenere Cipher")
st.caption("Vigenere Cipher 26 huruf alfabet — mendukung teks dan file sembarang.")

with st.sidebar:
    st.header("Pengaturan")
    mode = st.radio("Mode", ["Enkripsi", "Dekripsi"])
    kind = st.radio("Jenis pesan", ["Teks", "File"])
    raw_key = st.text_input("Kunci (huruf A–Z)", type="password",
                            help="Panjang kunci bebas. Selain huruf akan diabaikan.")
    key = clean_letters(raw_key)
    if raw_key and not key:
        st.error("Kunci harus mengandung minimal satu huruf.")
    elif key:
        st.caption(f"Kunci efektif: {len(key)} huruf")
    fmt = None
    if kind == "Teks" and mode == "Enkripsi":
        fmt = st.radio("Format cipherteks", ["Tanpa spasi", "Kelompok 5 huruf"])

encrypting = mode == "Enkripsi"

# ------------------------------------------------------------------ Mode teks
if kind == "Teks":
    src = st.radio("Sumber pesan", ["Ketik dari keyboard", "Unggah file teks (.txt)"],
                   horizontal=True)
    text = ""
    label = "Plainteks" if encrypting else "Cipherteks"
    if src.startswith("Ketik"):
        text = st.text_area(label, height=180)
    else:
        up = st.file_uploader("File teks", type=["txt"])
        if up is not None:
            text = up.getvalue().decode("utf-8", errors="ignore")
            st.text_area(f"Isi file ({label.lower()})", text, height=140, disabled=True)

    if text and key:
        letters = clean_letters(text)
        if not letters:
            st.warning("Tidak ada karakter alfabet pada pesan.")
        elif encrypting:
            ct = vigenere_text(letters, key)
            shown = group5(ct) if fmt == "Kelompok 5 huruf" else ct
            st.subheader("Hasil")
            st.markdown("**Plainteks (huruf saja):**")
            st.code(letters, language=None)
            st.markdown("**Cipherteks:**")
            st.code(shown, language=None)
            st.download_button("💾 Simpan cipherteks (.txt)", shown,
                               file_name="cipherteks.txt", mime="text/plain")
        else:
            pt = vigenere_text(letters, key, decrypt=True)
            st.subheader("Hasil")
            st.markdown("**Cipherteks:**")
            st.code(group5(letters), language=None)
            st.markdown("**Plainteks:**")
            st.code(pt, language=None)
            st.download_button("💾 Simpan plainteks (.txt)", pt,
                               file_name="plainteks.txt", mime="text/plain")
    elif text and not key:
        st.info("Masukkan kunci di sidebar.")

# ------------------------------------------------------------------ Mode file
else:
    if encrypting:
        up = st.file_uploader("Pilih file apa saja (teks / biner)")
        if up is not None and key:
            data = up.getvalue()
            out = encrypt_file(data, up.name, key)
            st.success(f"'{up.name}' ({len(data):,} byte) berhasil dienkripsi.")
            st.download_button("💾 Unduh file cipherteks (.dat)", out,
                               file_name=os.path.splitext(up.name)[0] + ".dat",
                               mime="application/octet-stream")
            st.caption("Nama & ekstensi file asli disimpan di dalam cipherteks "
                       "sehingga otomatis dipulihkan saat dekripsi.")
        elif up is not None:
            st.info("Masukkan kunci di sidebar.")
    else:
        up = st.file_uploader("Pilih file cipherteks (.dat)", type=["dat"])
        if up is not None and key:
            result = decrypt_file(up.getvalue(), key)
            if result is None:
                st.error("Dekripsi gagal: kunci salah atau file bukan cipherteks "
                         "dari aplikasi ini.")
            else:
                name, data = result
                st.success(f"Berhasil didekripsi → '{name}' ({len(data):,} byte).")
                st.download_button(f"💾 Unduh {name}", data, file_name=name,
                                   mime="application/octet-stream")
        elif up is not None:
            st.info("Masukkan kunci di sidebar.")

with st.expander("ℹ️ Catatan implementasi"):
    st.markdown(
        """
- **Teks**: hanya huruf A–Z yang dienkripsi; angka, spasi, dan tanda baca dibuang.
  Rumus: `C = (P + K) mod 26`, `P = (C − K) mod 26`.
- **File**: seluruh byte (termasuk header file) dienkripsi dengan
  `C = (B + K) mod 256`, di mana `K` = nilai huruf kunci (A=0…Z=25), agar file biner
  bisa dipulihkan persis sama.
- Nama file asli disimpan (terenkripsi) di awal cipherteks, beserta penanda
  untuk mendeteksi kunci yang salah.
        """
    )
