"""
Generates the synthetic test corpus and an independently computed expected-results
manifest. Expected values come from Python's hashlib and a separate entropy
implementation, NOT from the Kotlin engine, so tests compare against a second implementation.
"""
import hashlib, math, os, random, struct, zipfile, io, csv

OUT = "engine/src/test/resources/corpus"
os.makedirs(OUT, exist_ok=True)

def write(name, data: bytes):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)

def shannon(data: bytes) -> float:
    if not data: return 0.0
    counts = [0]*256
    for b in data: counts[b] += 1
    n = len(data); h = 0.0
    for c in counts:
        if c:
            p = c/n; h -= p*math.log2(p)
    return h

rng = random.Random(20260101)  # fixed seed for reproducibility

files = {}

# 1. Genuine PNG signature with a tiny valid-looking body (identification only).
files["genuine.png"] = bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]) + b"\x00\x00\x00\x0DIHDR" + b"\x00"*17

# 2. JPEG with SOI + APP0 JFIF marker prefix.
files["genuine.jpg"] = bytes([0xFF,0xD8,0xFF,0xE0,0x00,0x10]) + b"JFIF\x00" + b"\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\xFF\xD9"

# 3. Misleading extension: a PNG stored as photo.jpg.
files["actually_png.jpg"] = files["genuine.png"]

# 4. PDF header.
files["document.pdf"] = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

# 5. Genuine ZIP built by the real zipfile module.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("hello.txt", "hello forensic world\n" * 20)
files["archive.zip"] = buf.getvalue()

# 6. SQLite header.
files["database.sqlite"] = b"SQLite format 3\x00" + b"\x10\x00" + b"\x00"*(100-18)

# 7. Uniform distribution: every byte value exactly once -> exactly 8.0 bits/byte.
files["uniform_256.bin"] = bytes(range(256))

# 8. All zeros -> exactly 0.0 bits/byte.
files["zeros_1024.bin"] = b"\x00"*1024

# 9. Two equally likely symbols -> exactly 1.0 bit/byte.
files["two_symbols.bin"] = b"AB"*512

# 10. Pseudorandom bytes (seeded) -> high entropy but NOT proof of encryption.
files["random_4096.bin"] = bytes(rng.getrandbits(8) for _ in range(4096))

# 11. Text with embedded printable strings (ASCII + UTF-16LE).
ascii_part = b"\x00\x01\x02HelloWorldString\x00\x7f"
utf16_part = "Wide Text Here".encode("utf-16-le")
files["strings_mixed.bin"] = b"\xff\xfe\x01" + ascii_part + b"\x80\x81" + utf16_part + b"\x00\x00"

# 12. TAR ustar magic at offset 257 (identifier must find it past offset 0).
tar = bytearray(512)
tar[257:262] = b"ustar"
files["archive.tar"] = bytes(tar)

# 13. Appended payload: valid PNG with a ZIP appended after IEND.
png_iend = bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]) + b"\x00"*20 + b"IEND\xaeB`\x82"
files["png_with_appended_zip.png"] = png_iend + buf.getvalue()

# 14. Unknown binary: no signature should match.
files["unknown.bin"] = bytes([0x12,0x34,0x56,0x78,0x9A,0xBC,0xDE,0xF0]) * 8

# 15. Truncated PNG: only 3 bytes of signature.
files["truncated.png"] = bytes([0x89,0x50,0x4E])

for name, data in files.items():
    write(name, data)

# Independently computed expectations.
rows = []
for name, data in sorted(files.items()):
    rows.append({
        "file": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entropy": f"{shannon(data):.6f}",
    })

with open(os.path.join(OUT, "expected.tsv"), "w", newline="") as f:
    w = csv.writer(f, delimiter="\t")
    w.writerow(["file","size","sha256","entropy_bits_per_byte"])
    for r in rows:
        w.writerow([r["file"], r["size"], r["sha256"], r["entropy"]])

for r in rows: print(r["file"], r["size"], r["entropy"], r["sha256"][:16])
