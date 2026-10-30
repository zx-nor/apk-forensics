#!/usr/bin/env python3
"""
Generates the Milestone 2 synthetic corpus and its expected results.

Independence: fixtures are produced by tools that are NOT the engine under test:
Python zipfile / sqlite3 / hashlib, PIL (images, EXIF, PNG/WebP text), aapt2 (binary manifests),
openssl (certificates and PKCS#7), and the Info-ZIP `zip` CLI (ZipCrypto). Expected values are
the generator's own inputs or values derived with those tools, never engine output.

Run from the project root:  python3 tools/make_fixtures_m2.py
"""
import datetime, hashlib, io, os, random, shutil, sqlite3, struct, subprocess, zipfile, tempfile, math
from PIL import Image, PngImagePlugin
from PIL.TiffImagePlugin import IFDRational

OUT = "engine/src/test/resources/corpus2"
EXPECT_PATH = os.path.join(OUT, "expected_m2.tsv")
os.makedirs(OUT, exist_ok=True)
for f in os.listdir(OUT):
    os.remove(os.path.join(OUT, f))

expect = []  # (file, key, value)
def exp(file, key, value):
    expect.append((file, key, str(value)))

def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)

def zip_bytes(entries, compress=zipfile.ZIP_DEFLATED, comment=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compress) as z:
        for name, data in entries:
            z.writestr(name, data, compress_type=compress)
        if comment:
            z.comment = comment
    return buf.getvalue()

rng = random.Random(2026)

# ---------------------------------------------------------------- OOXML packages
CT = b'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>'
CORE = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>Quarterly Report</dc:title><dc:creator>Alice Analyst</dc:creator><cp:keywords>finance; Q3</cp:keywords>
<cp:lastModifiedBy>Bob Editor</cp:lastModifiedBy><cp:revision>4</cp:revision>
<dcterms:created xsi:type="dcterms:W3CDTF">2024-05-01T10:00:00Z</dcterms:created>
<dcterms:modified xsi:type="dcterms:W3CDTF">2024-05-02T11:30:00Z</dcterms:modified></cp:coreProperties>'''
APP = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Microsoft Office Word</Application><Company>Acme Corp</Company><Pages>3</Pages><Words>1200</Words></Properties>'''
CUSTOM = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property fmtid="{D5CDD505-2E9C-101B-9397-08002B2CF9AE}" pid="2" name="Project"><vt:lpwstr>Falcon</vt:lpwstr></property></Properties>'''

docx = zip_bytes([
    ("[Content_Types].xml", CT), ("word/document.xml", b"<w:document/>"),
    ("docProps/core.xml", CORE), ("docProps/app.xml", APP), ("docProps/custom.xml", CUSTOM),
])
write("report.docx", docx)
exp("report.docx", "refined", "docx")
exp("report.docx", "zipkind", "DOCX")
exp("report.docx", "meta.status", "EXTRACTED")
exp("report.docx", "field:OOXML.core|Title", "Quarterly Report")
exp("report.docx", "field:OOXML.core|Creator", "Alice Analyst")
exp("report.docx", "field:OOXML.core|LastModifiedBy", "Bob Editor")
exp("report.docx", "field:OOXML.core|Revision", "4")
exp("report.docx", "field:OOXML.core|Created", "2024-05-01T10:00:00Z")
exp("report.docx", "field:OOXML.core|Keywords", "finance; Q3")
exp("report.docx", "field:OOXML.app|Application", "Microsoft Office Word")
exp("report.docx", "field:OOXML.app|Pages", "3")
exp("report.docx", "field:OOXML.custom|Project", "Falcon")
exp("report.docx", "mismatch", "false")

write("workbook.xlsx", zip_bytes([("[Content_Types].xml", CT), ("xl/workbook.xml", b"<workbook/>"),
                                 ("docProps/app.xml", APP)]))
exp("workbook.xlsx", "refined", "xlsx"); exp("workbook.xlsx", "zipkind", "XLSX")
exp("workbook.xlsx", "meta.status", "EXTRACTED")
exp("workbook.xlsx", "field:OOXML.app|Company", "Acme Corp")

write("deck.pptx", zip_bytes([("[Content_Types].xml", CT), ("ppt/presentation.xml", b"<p:presentation/>")]))
exp("deck.pptx", "refined", "pptx"); exp("deck.pptx", "zipkind", "PPTX")
exp("deck.pptx", "meta.status", "NO_METADATA_PRESENT")  # structure only, no docProps part

# Ordinary ZIP with no office markers.
write("plain.zip", zip_bytes([("hello.txt", b"hello forensic world\n" * 20), ("notes/readme.md", b"# notes\n")]))
exp("plain.zip", "refined", "zip"); exp("plain.zip", "zipkind", "ZIP")
exp("plain.zip", "meta.status", "NOT_SUPPORTED")

# Misleading: a real ZIP named .pdf
write("archive_disguised.pdf", zip_bytes([("data.txt", b"not a pdf")]))
exp("archive_disguised.pdf", "refined", "zip"); exp("archive_disguised.pdf", "mismatch", "true")
exp("archive_disguised.pdf", "finding:EXTENSION_MISMATCH", "")

# Misleading: a DOCX named .jar
write("notes_as_jar.jar", docx)
exp("notes_as_jar.jar", "refined", "docx"); exp("notes_as_jar.jar", "mismatch", "true")

# JAR with META-INF/MANIFEST.MF only.
write("library.jar", zip_bytes([("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\r\n"), ("com/x/Y.class", b"\xCA\xFE\xBA\xBE")]))
exp("library.jar", "refined", "jar"); exp("library.jar", "zipkind", "JAR")

# Ambiguous: APK markers and OOXML markers together.
write("ambiguous.zip", zip_bytes([("AndroidManifest.xml", b"x"), ("classes.dex", b"dex"), ("[Content_Types].xml", CT), ("word/document.xml", b"x")]))
exp("ambiguous.zip", "zipkind", "AMBIGUOUS_OFFICE_OR_APK")
exp("ambiguous.zip", "refined", "zip")

# ---------------------------------------------------------------- APK via aapt2 + openssl
tmp = tempfile.mkdtemp(prefix="bbf-apk-")
manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.demo" android:versionCode="7" android:versionName="1.2.3">
<uses-sdk android:minSdkVersion="29" android:targetSdkVersion="34"/>
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.CAMERA" android:maxSdkVersion="30"/>
<application android:label="Demo" android:debuggable="true" android:allowBackup="false">
<activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity>
<service android:name="com.example.demo.SyncService" android:exported="false"/>
<receiver android:name=".BootReceiver" android:exported="true" android:permission="android.permission.RECEIVE_BOOT_COMPLETED"><intent-filter><action android:name="android.intent.action.BOOT_COMPLETED"/></intent-filter></receiver>
</application></manifest>'''
mpath = os.path.join(tmp, "AndroidManifest.xml")
open(mpath, "w").write(manifest)
subprocess.run(["aapt2", "link", "-o", os.path.join(tmp, "base.apk"), "-I",
                "/usr/lib/android-sdk/platforms/android-23/android.jar", "--manifest", mpath], check=True, capture_output=True)
with zipfile.ZipFile(os.path.join(tmp, "base.apk")) as z:
    base_entries = [(n, z.read(n)) for n in z.namelist()]
subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", os.path.join(tmp, "key.pem"),
                "-out", os.path.join(tmp, "cert.pem"), "-days", "3650", "-subj", "/CN=Blackbox Test Signer"],
               check=True, capture_output=True)
dex = b"dex\n035\x00" + b"\x00" * 32
mf = b"Manifest-Version: 1.0\r\nCreated-By: fixture\r\n\r\n"
subprocess.run(["openssl", "smime", "-sign", "-binary", "-in", os.path.join(tmp, "AndroidManifest.xml"),
                "-signer", os.path.join(tmp, "cert.pem"), "-inkey", os.path.join(tmp, "key.pem"),
                "-outform", "DER", "-nodetach", "-out", os.path.join(tmp, "CERT.RSA")], check=True, capture_output=True)
cert_rsa = open(os.path.join(tmp, "CERT.RSA"), "rb").read()
apk_entries = base_entries + [("classes.dex", dex), ("META-INF/MANIFEST.MF", mf), ("META-INF/CERT.RSA", cert_rsa)]
write("demo.apk", zip_bytes(apk_entries))

# Independent expected values: openssl reports the DER fingerprint and validity dates.
der = subprocess.run(["openssl", "x509", "-in", os.path.join(tmp, "cert.pem"), "-outform", "DER"], check=True, capture_output=True).stdout
fp = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
dates = subprocess.run(["openssl", "x509", "-in", os.path.join(tmp, "cert.pem"), "-noout", "-startdate", "-enddate"],
                       check=True, capture_output=True, text=True).stdout.splitlines()
def iso(line):
    s = line.split("=", 1)[1]
    d = datetime.datetime.strptime(s, "%b %d %H:%M:%S %Y %Z")
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")
serial_hex = subprocess.run(["openssl", "x509", "-in", os.path.join(tmp, "cert.pem"), "-noout", "-serial"],
                            check=True, capture_output=True, text=True).stdout.strip().split("=", 1)[1]
shutil.rmtree(tmp, ignore_errors=True)

exp("demo.apk", "refined", "apk"); exp("demo.apk", "zipkind", "APK")
exp("demo.apk", "meta.status", "EXTRACTED")
exp("demo.apk", "field:APK.manifest|Package", "com.example.demo")
exp("demo.apk", "field:APK.manifest|VersionCode", "7")
exp("demo.apk", "field:APK.manifest|VersionName", "1.2.3")
exp("demo.apk", "field:APK.sdk|MinSdkVersion", "29")
exp("demo.apk", "field:APK.sdk|TargetSdkVersion", "34")
exp("demo.apk", "field:APK.permission|uses-permission", "android.permission.INTERNET")
exp("demo.apk", "field:APK.permission|uses-permission", "android.permission.CAMERA maxSdk=30")
exp("demo.apk", "field:APK.application|Debuggable", "true")
exp("demo.apk", "field:APK.application|AllowBackup", "false")
exp("demo.apk", "field:APK.application|Label", "Demo")
exp("demo.apk", "field:APK.component|activity", "com.example.demo.MainActivity exported=true actions=[android.intent.action.MAIN] launcher=yes")
exp("demo.apk", "field:APK.component|service", "com.example.demo.SyncService exported=false")
exp("demo.apk", "field:APK.component|receiver", "com.example.demo.BootReceiver exported=true permission=android.permission.RECEIVE_BOOT_COMPLETED actions=[android.intent.action.BOOT_COMPLETED]")
exp("demo.apk", "field:APK.signer|Subject", "CN=Blackbox Test Signer")
exp("demo.apk", "field:APK.signer|Issuer", "CN=Blackbox Test Signer")
exp("demo.apk", "field:APK.signer|SerialNumber", format(int(serial_hex, 16), "x"))
exp("demo.apk", "field:APK.signer|SHA256Fingerprint", fp)
exp("demo.apk", "field:APK.signer|NotBefore", iso(dates[0]))
exp("demo.apk", "field:APK.signer|NotAfter", iso(dates[1]))
exp("demo.apk", "field:structure|DexFileCount", "1")
exp("demo.apk", "field:structure|SigningBlockV2V3Present", "no")
exp("demo.apk", "note:Signer certificates were parsed", "")

# ---------------------------------------------------------------- ZIP structural fixtures
# Path traversal and deception.
trav = zip_bytes([("../../etc/evil.sh", b"x"), ("/abs/root.txt", b"x"), ("C:/Windows/system.exe", b"x"),
                  ("back\\slash.txt", b"x"), ("dup.txt", b"1"), ("dup.txt", b"2"), ("ok.txt", b"fine")])
write("traversal.zip", trav)
for code in ["PATH_TRAVERSAL", "ABSOLUTE_PATH", "DRIVE_LETTER_PATH", "BACKSLASH_SEPARATOR", "DUPLICATE_ENTRY_NAME", "EXECUTABLE_CONTENT_PRESENT"]:
    exp("traversal.zip", f"finding:{code}", "")
exp("traversal.zip", "entries", "7")

# Decompression bomb: 20 MiB of zeros in ~20 KB.
bomb_payload = b"\x00" * (20 * 1024 * 1024)
write("bomb.zip", zip_bytes([("payload.bin", bomb_payload)]))
exp("bomb.zip", "finding:EXCESSIVE_COMPRESSION_RATIO", "")
exp("bomb.zip", "entry:payload.bin|measured", str(20 * 1024 * 1024))
exp("bomb.zip", "entry:payload.bin|crc", "ok")

# ZipCrypto via Info-ZIP zip -P.
with tempfile.TemporaryDirectory() as d:
    src = os.path.join(d, "secret.txt")
    open(src, "wb").write(b"classified contents\n" * 10)
    dst = os.path.join(d, "enc.zip")
    subprocess.run(["zip", "-q", "-P", "pass123", "-j", dst, src], check=True)
    write("encrypted_zipcrypto.zip", open(dst, "rb").read())
exp("encrypted_zipcrypto.zip", "zip.enc:secret.txt", "TRADITIONAL_PKWARE_ZIPCRYPTO")
exp("encrypted_zipcrypto.zip", "finding:ENCRYPTED_ENTRY", "")

# WinZip AES entry, hand-packed (header structure only; data is not decryptable here).
def aes_zip():
    name = b"vault.bin"
    data = bytes(rng.getrandbits(8) for _ in range(32))
    extra = struct.pack("<HHHBH", 0x9901, 7, 2, 0, 0)  # placeholder, rewritten below
    extra = struct.pack("<HHH", 0x9901, 7, 2) + b"AE" + struct.pack("<BH", 3, 8)  # strength 3 = 256-bit, actual method 8
    local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 51, 1, 99, 0, 0, 0, len(data), len(data), len(name), len(extra)) + name + extra + data
    cd = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 51, 51, 1, 99, 0, 0, 0, len(data), len(data), len(name), len(extra), 0, 0, 0, 0, 0) + name + extra
    cd_off = len(local)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), cd_off, 0)
    return local + cd + eocd
write("aes_synthetic.zip", aes_zip())
exp("aes_synthetic.zip", "zip.enc:vault.bin", "WINZIP_AES")
exp("aes_synthetic.zip", "zip.enc.bits:vault.bin", "256")
exp("aes_synthetic.zip", "zip.enc.actual:vault.bin", "8")

# Nested archives.
inner = zip_bytes([("secret.txt", b"nested secret")])
write("nested.zip", zip_bytes([("readme.txt", b"outer"), ("inner.zip", inner)], compress=zipfile.ZIP_STORED))
exp("nested.zip", "nested:inner.zip", "ZIP")
exp("nested.zip", "nested.entry:inner.zip|secret.txt", "")
exp("nested.zip", "finding:NESTED_ARCHIVE", "")

# Five-level chain to exercise the nesting-depth limit (default 3).
chain = zip_bytes([("leaf.txt", b"bottom")], compress=zipfile.ZIP_STORED)
for lvl in range(5):
    chain = zip_bytes([(f"level{lvl}.zip", chain)], compress=zipfile.ZIP_STORED)
write("deep_nested.zip", chain)
exp("deep_nested.zip", "finding:NESTING_LIMIT_REACHED", "")

# Truncated mid-archive.
pz = open(os.path.join(OUT, "plain.zip"), "rb").read()
write("truncated.zip", pz[: int(len(pz) * 0.6)])
exp("truncated.zip", "refined", "zip-invalid")
exp("truncated.zip", "parseerror", "no end-of-central-directory signature found")

# Trailing bytes after the archive.
write("trailing.zip", pz + b"PAYLOAD-AFTER-ARCHIVE")
exp("trailing.zip", "zip.trailing", "21")
exp("trailing.zip", "finding:TRAILING_DATA_AFTER_ARCHIVE", "")

# Prepended data (self-extracting style): base identifier sees no magic at offset 0.
write("prepended.zip", b"#!/bin/sh\n" + pz)
exp("prepended.zip", "refined", "<none>")
exp("prepended.zip", "embedded:zip@10", "")
exp("prepended.zip", "zip.prepended", "10")

# Comment containing a fake end-of-central-directory signature.
fake = b"PK\x05\x06" + b"\x00" * 18
write("fake_eocd_comment.zip", zip_bytes([("a.txt", b"alpha"), ("b.txt", b"beta")], comment=fake))
exp("fake_eocd_comment.zip", "entries", "2")
exp("fake_eocd_comment.zip", "absent:EOCD_COMMENT_LENGTH_INCONSISTENT", "")
exp("fake_eocd_comment.zip", "finding:MULTIPLE_EOCD_SIGNATURES", "")

# Many entries (engine test sets a lower entry limit).
write("many_entries.zip", zip_bytes([(f"f{i:04d}.txt", f"{i}".encode()) for i in range(300)]))
exp("many_entries.zip", "entries", "300")

# ZIP64 entries forced by writer.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
    with z.open(zipfile.ZipInfo("big64.bin"), "w", force_zip64=True) as w:
        w.write(b"Z" * 70000)
write("zip64_entries.zip", buf.getvalue())
exp("zip64_entries.zip", "entry:big64.bin|measured", "70000")
exp("zip64_entries.zip", "entry:big64.bin|crc", "ok")

# Local header name differs from central directory name.
lname = bytearray(zip_bytes([("hello.txt", b"hello")], compress=zipfile.ZIP_STORED))
lname[30:39] = b"hellp.txt"
write("local_name_mismatch.zip", bytes(lname))
exp("local_name_mismatch.zip", "finding:LOCAL_NAME_MISMATCH", "")

# Data byte altered: CRC must fail.
crcbad = bytearray(zip_bytes([("data.txt", b"AAAAAAAA")], compress=zipfile.ZIP_STORED))
i = crcbad.find(b"AAAAAAAA")
crcbad[i] = ord("B")
write("crc_bad.zip", bytes(crcbad))
exp("crc_bad.zip", "finding:CRC_MISMATCH", "")

# Symbolic link entry pointing to an absolute path.
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w") as z:
    zi = zipfile.ZipInfo("link_to_etc")
    zi.create_system = 3
    zi.external_attr = (0o120777 & 0xFFFF) << 16
    z.writestr(zi, b"/etc/passwd", compress_type=zipfile.ZIP_STORED)
write("symlink.zip", buf.getvalue())
exp("symlink.zip", "finding:SYMLINK_ENTRY", "")
exp("symlink.zip", "finding:ABSOLUTE_PATH", "")

# Declared uncompressed size (central directory) disagrees with real size.
lie = bytearray(zip_bytes([("lie.txt", b"HELLO")], compress=zipfile.ZIP_STORED))
cd = lie.find(b"PK\x01\x02")
struct.pack_into("<I", lie, cd + 24, 9)
write("size_lie.zip", bytes(lie))
exp("size_lie.zip", "finding:DECLARED_SIZE_MISMATCH", "")

# Adversarial: central directory claims to be larger than the file.
huge = bytearray(pz)
eocd = huge.rfind(b"PK\x05\x06")
struct.pack_into("<I", huge, eocd + 12, 0x7FFFFFF0)
write("huge_cd_claim.zip", bytes(huge))
exp("huge_cd_claim.zip", "parseerror", "central directory size")

# Adversarial: APK manifest that is not binary XML.
write("bad_manifest.apk", zip_bytes([("AndroidManifest.xml", b"<manifest/>"), ("classes.dex", b"dex")]))
exp("bad_manifest.apk", "refined", "apk")
exp("bad_manifest.apk", "meta.status", "EXTRACTION_FAILED")

# ---------------------------------------------------------------- Images
def pil_exif():
    e = Image.Exif()
    e[0x010F] = "BlackboxCam"
    e[0x0110] = "Model-X1"
    e[0x0131] = "BBTest 1.0"
    e[0x0132] = "2024:05:01 12:00:00"
    ifd = e.get_ifd(0x8769)
    ifd[0x9003] = "2024:05:01 11:58:30"
    ifd[0x9011] = "+02:00"
    gps = e.get_ifd(0x8825)
    gps[1] = "N"; gps[2] = (IFDRational(37, 1), IFDRational(46, 1), IFDRational(297, 10))
    gps[3] = "W"; gps[4] = (IFDRational(122, 1), IFDRational(25, 1), IFDRational(98, 10))
    return e

def gps_decimal():
    lat = 37 + 46 / 60 + (297 / 10) / 3600
    lon = -(122 + 25 / 60 + (98 / 10) / 3600)
    return f"{lat:.6f}", f"{lon:.6f}"

img = Image.new("RGB", (64, 48), (200, 30, 30))
ex = pil_exif()
img.save(os.path.join(OUT, "exif_photo.jpg"), "JPEG", exif=ex.tobytes())
lat_s, lon_s = gps_decimal()
exp("exif_photo.jpg", "refined", "jpeg")
exp("exif_photo.jpg", "meta.status", "EXTRACTED")
exp("exif_photo.jpg", "field:EXIF|Make", "BlackboxCam")
exp("exif_photo.jpg", "field:EXIF|Model", "Model-X1")
exp("exif_photo.jpg", "field:EXIF|Software", "BBTest 1.0")
exp("exif_photo.jpg", "field:EXIF|DateTime", "2024:05:01 12:00:00")
exp("exif_photo.jpg", "field:EXIF.Exif|DateTimeOriginal", "2024:05:01 11:58:30")
exp("exif_photo.jpg", "field:EXIF.Exif|OffsetTimeOriginal", "+02:00")
exp("exif_photo.jpg", "field:EXIF.GPS|GPSLatitudeDecimal", lat_s)
exp("exif_photo.jpg", "field:EXIF.GPS|GPSLongitudeDecimal", lon_s)
exp("exif_photo.jpg", "field:structure|ImageWidth", "64")
exp("exif_photo.jpg", "field:structure|ImageHeight", "48")

img.save(os.path.join(OUT, "exif_photo.png"), "PNG", exif=ex)
info = PngImagePlugin.PngInfo()
info.add_text("Title", "Sample Title")
info.add_text("Comment", "zlib compressed note", zip=True)
info.add_itxt("Keywords", "alpha beta", lang="en", tkey="Keywords")
img.save(os.path.join(OUT, "text_photo.png"), "PNG", pnginfo=info, exif=ex)
exp("text_photo.png", "field:PNG.tEXt|Title", "Sample Title")
exp("text_photo.png", "field:PNG.zTXt|Comment", "zlib compressed note")
exp("text_photo.png", "field:PNG.iTXt|Keywords", "alpha beta")
exp("text_photo.png", "field:EXIF|Make", "BlackboxCam")
exp("text_photo.png", "field:structure|ImageWidth", "64")

img.save(os.path.join(OUT, "exif_photo.webp"), "WEBP", exif=ex.tobytes())
exp("exif_photo.webp", "refined", "webp")
exp("exif_photo.webp", "field:EXIF|Model", "Model-X1")
exp("exif_photo.webp", "field:structure|ImageWidth", "64")
exp("exif_photo.webp", "field:structure|ImageHeight", "48")

# Plain images: structure only, so NO_METADATA_PRESENT must be reported, not a failure.
img.save(os.path.join(OUT, "plain.jpg"), "JPEG")
img.save(os.path.join(OUT, "plain.png"), "PNG")
exp("plain.jpg", "meta.status", "NO_METADATA_PRESENT")
exp("plain.png", "meta.status", "NO_METADATA_PRESENT")
exp("plain.png", "field:structure|ImageWidth", "64")

# Appended and padded images.
jp = open(os.path.join(OUT, "plain.jpg"), "rb").read()
write("jpeg_appended.jpg", jp + b"ZZZZ")
exp("jpeg_appended.jpg", "appended.bytes", "4")
exp("jpeg_appended.jpg", "appended.zero", "false")
exp("jpeg_appended.jpg", "finding:APPENDED_DATA", "")
write("jpeg_padded.jpg", jp + b"\x00" * 16)
exp("jpeg_padded.jpg", "appended.bytes", "16")
exp("jpeg_padded.jpg", "appended.zero", "true")
exp("jpeg_padded.jpg", "finding:TRAILING_ZERO_PADDING", "")

pn = open(os.path.join(OUT, "plain.png"), "rb").read()
write("png_appended.png", pn + b"EVIL-PAYLOAD")
exp("png_appended.png", "appended.bytes", "12")
exp("png_appended.png", "appended.zero", "false")

# Embedded ZIP after a PNG: appended payload that is itself a container.
write("png_with_zip.png", pn + zip_bytes([("inside.txt", b"hidden")]))
exp("png_with_zip.png", "refined", "png")
exp("png_with_zip.png", "embedded:zip@", "")

# CRC corruption in the IHDR chunk.
bad = bytearray(pn)
bad[16 + 3] ^= 0xFF  # flip a byte in IHDR width
write("png_crc_bad.png", bytes(bad))
exp("png_crc_bad.png", "meta.status", "EXTRACTION_FAILED")
exp("png_crc_bad.png", "error:CRC mismatch in chunk IHDR", "")

# Hand-built TIFF with IFD0 and an Exif sub-IFD (little-endian).
def tiff_le(entries_ifd0, exif_entries):
    # Lay out: header(8) | IFD0 | Exif IFD | out-of-line data
    def ifd_bytes(entries, base):
        n = len(entries)
        size = 2 + 12 * n + 4
        data_off = base + size
        table = struct.pack("<H", n)
        blobs = b""
        for tag, typ, count, payload in entries:
            if len(payload) <= 4:
                val = payload.ljust(4, b"\x00")
            else:
                val = struct.pack("<I", data_off + len(blobs))
                blobs += payload + (b"\x00" if len(payload) % 2 else b"")
            table += struct.pack("<HHI", tag, typ, count) + val
        table += struct.pack("<I", 0)
        return table + blobs, base + size + len(blobs)
    exif_pos = 8 + 2 + 12 * (len(entries_ifd0) + 1) + 4  # placeholder; recomputed below
    ifd0_entries = list(entries_ifd0)
    # Pointer to Exif IFD appended as LONG; computed after IFD0 size is known.
    ifd0_len = 2 + 12 * (len(ifd0_entries) + 1) + 4
    ifd0_data_len = 0
    ifd0_probe, _ = ifd_bytes(ifd0_entries + [(0x8769, 4, 1, b"\x00\x00\x00\x00")], 8)
    exif_base = 8 + len(ifd0_probe)
    ifd0_final, _ = ifd_bytes(ifd0_entries + [(0x8769, 4, 1, struct.pack("<I", exif_base))], 8)
    exif_blob, _ = ifd_bytes(exif_entries, exif_base)
    return b"II*\x00" + struct.pack("<I", 8) + ifd0_final + exif_blob

tiff = tiff_le(
    [(0x0100, 3, 1, struct.pack("<H", 128)), (0x0101, 3, 1, struct.pack("<H", 96)),
     (0x010F, 2, 7, b"Tiffco\x00"), (0x0131, 2, 9, b"TiffSoft\x00")],
    [(0x9003, 2, 20, b"2023:12:31 23:59:59\x00")],
)
write("sample.tif", tiff)
exp("sample.tif", "refined", "tiff-le")
exp("sample.tif", "field:TIFF|ImageWidth", "128")
exp("sample.tif", "field:TIFF|ImageLength", "96")
exp("sample.tif", "field:TIFF|Make", "Tiffco")
exp("sample.tif", "field:TIFF|Software", "TiffSoft")
exp("sample.tif", "field:TIFF.Exif|DateTimeOriginal", "2023:12:31 23:59:59")

# Adversarial TIFF: an IFD that points to itself.
loop = bytearray(b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 1) + struct.pack("<HHI", 0x8769, 4, 1) + struct.pack("<I", 8) + struct.pack("<I", 0))
write("exif_loop.tif", bytes(loop))
exp("exif_loop.tif", "meta.status", "NO_METADATA_PRESENT")
exp("exif_loop.tif", "note:directory loop", "")

# ---------------------------------------------------------------- PDF
def pdf_build(info_dict, trailer_extra="", incremental=False):
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n",
        f"3 0 obj\n{info_dict}\nendobj\n".encode("latin-1"),
    ]
    body = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets = []
    for o in objs:
        offsets.append(len(body))
        body += o
    xref_at = len(body)
    xref = b"xref\n0 4\n0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()
    trailer = f"trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R {trailer_extra} >>\n".encode()
    body += xref + trailer + f"startxref\n{xref_at}\n%%EOF\n".encode()
    if incremental:
        extra_obj = b"4 0 obj\n<< /Producer (Updated) >>\nendobj\n"
        off4 = len(body)
        body += extra_obj
        xref2 = f"xref\n0 1\n0000000000 65535 f \n".encode() + f"4 1\n{off4:010d} 00000 n \n".encode()
        body += xref2 + f"trailer\n<< /Size 5 /Root 1 0 R /Info 3 0 R /Prev {xref_at} >>\nstartxref\n{len(body)-len(xref2)-len(b'trailer')}\n%%EOF\n".encode()
    return body

info = ("<< /Title (Quarterly \\(Q3\\) \\\\ Review) /Author <FEFF005A006F00EB0020005A0061> "
        "/Creator (Writer) /Producer (BlackboxPDF 1.0) /CreationDate (D:20240501120000+02'00') "
        "/ModDate (D:20240502) >>")
write("info.pdf", pdf_build(info))
exp("info.pdf", "refined", "pdf")
exp("info.pdf", "meta.status", "EXTRACTED")
exp("info.pdf", "field:PDF.Info|Title", "Quarterly (Q3) \\ Review")
exp("info.pdf", "field:PDF.Info|Author", "Zoë Za")
exp("info.pdf", "field:PDF.Info|Producer", "BlackboxPDF 1.0")
exp("info.pdf", "field:PDF.Info|CreationDate", "2024-05-01T12:00:00 (UTC+02:00)")
exp("info.pdf", "field:PDF.Info|ModDate", "2024-05-02T00:00:00 (no time zone recorded)")
exp("info.pdf", "field:structure|PDFVersion", "1.4")

write("encrypted.pdf", pdf_build("<< /Title (x) >>", trailer_extra="/Encrypt 9 0 R"))
exp("encrypted.pdf", "meta.status", "NOT_SUPPORTED")
exp("encrypted.pdf", "absent:PDF.Info|Title", "")

write("no_info.pdf", pdf_build("<< /Type /Metadata >>").replace(b"/Info 3 0 R ", b""))
exp("no_info.pdf", "meta.status", "NO_METADATA_PRESENT")

write("incremental.pdf", pdf_build(info, incremental=True))
exp("incremental.pdf", "finding:PDF_INCREMENTAL_UPDATES", "")
exp("incremental.pdf", "appended.zero", "false")

write("truncated_header.pdf", b"%PDF-1.7\n")
exp("truncated_header.pdf", "meta.status", "EXTRACTION_FAILED")

# ---------------------------------------------------------------- Audio
def syncsafe(n):
    return bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])

def id3_frame(fid, body):
    return fid.encode() + struct.pack(">I", len(body)) + b"\x00\x00" + body

title = id3_frame("TIT2", b"\x03" + b"Song Title")
artist = id3_frame("TPE1", b"\x01" + "Band".encode("utf-16") )  # BOM included by utf-16 codec
album = id3_frame("TALB", b"\x00" + b"Album One")
year = id3_frame("TYER", b"\x00" + b"2023")
genre = id3_frame("TCON", b"\x00" + b"Rock")
comm = id3_frame("COMM", b"\x00" + b"eng" + b"\x00" + b"note here")
apic = id3_frame("APIC", b"\x00" + b"image/png\x00" + b"\x03" + b"cover\x00" + b"\x89PNG-data")
frames = title + artist + album + year + genre + comm + apic
tag = b"ID3" + b"\x03\x00" + b"\x00" + syncsafe(len(frames)) + frames
mp3_frame = b"\xFF\xFB\x90\x64" + b"\x00" * 413
id3v1 = b"TAG" + b"V1 Title".ljust(30, b"\x00") + b"V1 Artist".ljust(30, b"\x00") + b"V1 Album".ljust(30, b"\x00") + b"1999" + b"v1 comment".ljust(30, b"\x00") + b"\x11"
write("tagged.mp3", tag + mp3_frame * 3 + id3v1)
exp("tagged.mp3", "refined", "mp3-id3")
exp("tagged.mp3", "meta.status", "EXTRACTED")
exp("tagged.mp3", "field:ID3|Title", "Song Title")
exp("tagged.mp3", "field:ID3|Artist", "Band")
exp("tagged.mp3", "field:ID3|Album", "Album One")
exp("tagged.mp3", "field:ID3|Year", "2023")
exp("tagged.mp3", "field:ID3|Genre", "Rock")
exp("tagged.mp3", "field:ID3.COMM|Comment[eng]", "note here")
exp("tagged.mp3", "field:ID3.APIC|Picture", "type=3 mime=image/png bytes=" + str(len(b"\x89PNG-data")))
exp("tagged.mp3", "field:ID3v1|Title", "V1 Title")
exp("tagged.mp3", "field:ID3v1|Year", "1999")
exp("tagged.mp3", "field:structure|MPEGVersion", "MPEG-1")
exp("tagged.mp3", "field:structure|Layer", "Layer III")
exp("tagged.mp3", "field:structure|BitrateKbpsFirstFrame", "128")
exp("tagged.mp3", "field:structure|SampleRateHz", "44100")
exp("tagged.mp3", "field:structure|ChannelMode", "joint stereo")

# FLAC: STREAMINFO bit packing, then optional VORBIS_COMMENT and PICTURE blocks.
def streaminfo(rate, channels, bps, samples, md5):
    b = struct.pack(">HH", 4096, 4096) + b"\x00\x00\x00" + b"\x00\x00\x00"
    packed = (rate << 44) | ((channels - 1) << 41) | ((bps - 1) << 36) | samples
    b += packed.to_bytes(8, "big") + md5
    assert len(b) == 34, len(b)
    return b

def block(btype, body, last):
    return bytes([(0x80 if last else 0) | btype]) + len(body).to_bytes(3, "big") + body

md5 = bytes(range(16))
si = streaminfo(44100, 2, 16, 441000, md5)
vendor = b"ref libFLAC 1.4"
vc_entries = [b"TITLE=Flac Song", b"ARTIST=Flac Artist", b"DATE=2022"]
vc = struct.pack("<I", len(vendor)) + vendor + struct.pack("<I", len(vc_entries))
for e in vc_entries:
    vc += struct.pack("<I", len(e)) + e
pic = struct.pack(">I", 3) + struct.pack(">I", 9) + b"image/png" + struct.pack(">I", 0) + struct.pack(">IIII", 1, 1, 24, 0) + struct.pack(">I", 4) + b"\x89PNG"
write("tagged.flac", b"fLaC" + block(0, si, False) + block(4, vc, False) + block(6, pic, True) + b"\x00" * 64)
exp("tagged.flac", "refined", "flac")
exp("tagged.flac", "field:FLAC.Vorbis|TITLE", "Flac Song")
exp("tagged.flac", "field:FLAC.Vorbis|ARTIST", "Flac Artist")
exp("tagged.flac", "field:FLAC.Vorbis|DATE", "2022")
exp("tagged.flac", "field:FLAC.Picture|Picture", "type=3 mime=image/png bytes=4")
exp("tagged.flac", "field:structure|SampleRateHz", "44100")
exp("tagged.flac", "field:structure|Channels", "2")
exp("tagged.flac", "field:structure|BitsPerSample", "16")
exp("tagged.flac", "field:structure|TotalSamples", "441000")
exp("tagged.flac", "field:structure|DurationSeconds", "10.000")
exp("tagged.flac", "field:structure|StreamMD5", md5.hex())

write("bare.flac", b"fLaC" + block(0, streaminfo(48000, 1, 24, 96000, b"\x00" * 16), True))
exp("bare.flac", "meta.status", "NO_METADATA_PRESENT")
exp("bare.flac", "note:STREAMINFO MD5 is zero", "")

def wav_build(info_chunks=b"", bext=None, riff_extra=0, trunc=False):
    fmt = struct.pack("<HHIIHH", 1, 1, 22050, 44100, 2, 16)
    data = b"\x01\x02" * 22050  # 44100 bytes = 1.000 s at 44100 B/s
    body = b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt + b"data" + struct.pack("<I", len(data)) + data
    if bext is not None:
        body += b"bext" + struct.pack("<I", len(bext)) + bext
    body += info_chunks
    riff = b"RIFF" + struct.pack("<I", len(body) + riff_extra) + body
    return riff

def riff_sub(fourcc, payload):
    pad = b"\x00" if len(payload) % 2 else b""
    return fourcc + struct.pack("<I", len(payload)) + payload + pad
_subs = riff_sub(b"INAM", b"Wav Title\x00") + riff_sub(b"IART", b"Wav Artist\x00") + riff_sub(b"ICRD", b"2021-03-04\x00")
info_list = b"LIST" + struct.pack("<I", 4 + len(_subs)) + b"INFO" + _subs
bext_body = b"Field recording".ljust(256, b"\x00") + b"Recorder".ljust(32, b"\x00") + b"x" * 32 + b"2021-03-04" + b"12:00:00" + b"\x00" * 8 + b"\x00" * 2 + b"\x00" * 64
write("tagged.wav", wav_build(info_list, bext=bext_body))
exp("tagged.wav", "refined", "wav")
exp("tagged.wav", "field:WAV.INFO|Title", "Wav Title")
exp("tagged.wav", "field:WAV.INFO|Artist", "Wav Artist")
exp("tagged.wav", "field:WAV.INFO|CreationDate", "2021-03-04")
exp("tagged.wav", "field:WAV.bext|Description", "Field recording")
exp("tagged.wav", "field:structure|SampleRateHz", "22050")
exp("tagged.wav", "field:structure|DurationSeconds", "1.000")

write("bare.wav", wav_build())
exp("bare.wav", "meta.status", "NO_METADATA_PRESENT")

write("wav_appended.wav", wav_build() + b"TRAILER")
exp("wav_appended.wav", "appended.bytes", "7")
exp("wav_appended.wav", "appended.zero", "false")

write("wav_truncated.wav", wav_build()[:-500])
exp("wav_truncated.wav", "finding:RIFF_SIZE_EXCEEDS_FILE", "")

# ---------------------------------------------------------------- MP4 / MOV
def box(t, body):
    return struct.pack(">I", 8 + len(body)) + t.encode("latin-1") + body

def fullbox(t, version, flags, body):
    return box(t, bytes([version]) + flags.to_bytes(3, "big") + body)

def secs1904(dt):
    return int((dt - datetime.datetime(1904, 1, 1)).total_seconds())

created = secs1904(datetime.datetime(2024, 5, 1, 12, 0, 0))
mvhd = fullbox("mvhd", 0, 0, struct.pack(">IIII", created, created, 1000, 5000) + b"\x00" * 80)
eng = ((ord("e") - 0x60) << 10) | ((ord("n") - 0x60) << 5) | (ord("g") - 0x60)
tkhd = fullbox("tkhd", 0, 3, b"\x00" * 8 + struct.pack(">I", 1) + b"\x00" * 4 + struct.pack(">I", 5000) + b"\x00" * 52 + struct.pack(">II", 320 << 16, 240 << 16))
mdhd = fullbox("mdhd", 0, 0, struct.pack(">IIIIHH", created, created, 1000, 5000, eng, 0))
hdlr_v = fullbox("hdlr", 0, 0, b"\x00" * 4 + b"vide" + b"\x00" * 12 + b"VideoHandler\x00")
stsd_v = fullbox("stsd", 0, 0, struct.pack(">I", 1) + box("avc1", b"\x00" * 78))
stbl_v = box("stbl", stsd_v)
minf_v = box("minf", stbl_v)
mdia_v = box("mdia", mdhd + hdlr_v + minf_v)
trak_v = box("trak", tkhd + mdia_v)
hdlr_a = fullbox("hdlr", 0, 0, b"\x00" * 4 + b"soun" + b"\x00" * 12 + b"SoundHandler\x00")
stsd_a = fullbox("stsd", 0, 0, struct.pack(">I", 1) + box("mp4a", b"\x00" * 28))
trak_a = box("trak", box("mdia", mdhd + hdlr_a + box("minf", box("stbl", stsd_a))))
ilst = box("ilst",
    box("\xa9nam", box("data", struct.pack(">I", 1) + b"\x00" * 4 + "Clip Title".encode("utf-8"))) +
    box("\xa9ART", box("data", struct.pack(">I", 1) + b"\x00" * 4 + "Clip Artist".encode("utf-8"))) +
    box("\xa9day", box("data", struct.pack(">I", 1) + b"\x00" * 4 + "2024".encode("utf-8"))))
meta_iso = fullbox("meta", 0, 0, fullbox("hdlr", 0, 0, b"\x00" * 4 + b"mdir" + b"\x00" * 9 + b"\x00") + ilst)
loc_text = "+37.7749-122.4194/".encode("utf-8")
xyz = box("\xa9xyz", struct.pack(">HH", len(loc_text), 0) + loc_text)
udta = box("udta", meta_iso + xyz)
moov = box("moov", mvhd + trak_v + trak_a + udta)
ftyp = box("ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2avc1mp41")
write("clip.mp4", ftyp + moov + box("mdat", b"\x00" * 64))
exp("clip.mp4", "refined", "mp4")
exp("clip.mp4", "meta.status", "EXTRACTED")
exp("clip.mp4", "field:structure|MajorBrand", "isom")
exp("clip.mp4", "field:MovieHeader|CreationTime", "2024-05-01T12:00:00Z (UTC, as recorded by writer)")
exp("clip.mp4", "field:structure|DurationSeconds", "5.000")
exp("clip.mp4", "field:MP4.track1|HandlerType", "vide")
exp("clip.mp4", "field:MP4.track1|Codec", "avc1")
exp("clip.mp4", "field:MP4.track1|Width", "320")
exp("clip.mp4", "field:MP4.track1|Height", "240")
exp("clip.mp4", "field:MP4.track1|Language", "eng")
exp("clip.mp4", "field:MP4.track2|Codec", "mp4a")
exp("clip.mp4", "field:MP4.ilst|Title", "Clip Title")
exp("clip.mp4", "field:MP4.ilst|Artist", "Clip Artist")
exp("clip.mp4", "field:MP4.ilst|Date", "2024")
exp("clip.mp4", "field:MP4.udta|Location", "+37.7749-122.4194/")

# QuickTime: mvhd creation time zero means "not set", which must be reported as absent, not as a date.
mvhd_zero = fullbox("mvhd", 0, 0, struct.pack(">IIII", 0, 0, 600, 1200) + b"\x00" * 80)
mov = box("ftyp", b"qt  " + b"\x00\x00\x00\x00" + b"qt  ") + box("moov", mvhd_zero)
write("clip.mov", mov)
exp("clip.mov", "refined", "mov")
exp("clip.mov", "absent:MovieHeader|CreationTime", "")
exp("clip.mov", "note:MovieHeader.CreationTime is zero", "")

# Adversarial: a box that claims more bytes than its container holds.
bad_box = struct.pack(">I", 9999) + b"moov" + b"\x00" * 8
write("bad_box.mp4", box("ftyp", b"isom" + b"\x00" * 4 + b"isom") + bad_box)
exp("bad_box.mp4", "meta.status", "EXTRACTION_FAILED")

# ---------------------------------------------------------------- SQLite
dbp = os.path.join(OUT, "sample.db")
if os.path.exists(dbp):
    os.remove(dbp)
con = sqlite3.connect(dbp)
con.execute("PRAGMA page_size=4096")
con.execute("CREATE TABLE t(a INTEGER, b TEXT)")
con.executemany("INSERT INTO t VALUES (?,?)", [(i, f"row {i}") for i in range(200)])
con.execute("PRAGMA user_version=7")
con.execute("PRAGMA application_id=4660")
con.commit()
con.close()
data = open(dbp, "rb").read()
pages = struct.unpack(">I", data[28:32])[0]
sqver = sqlite3.sqlite_version_info
exp("sample.db", "refined", "sqlite3")
exp("sample.db", "meta.status", "EXTRACTED")
exp("sample.db", "field:structure|PageSize", "4096")
exp("sample.db", "field:structure|TextEncoding", "UTF-8")
exp("sample.db", "field:structure|DatabasePages", str(pages))
exp("sample.db", "field:DB.Header|UserVersion", "7")
exp("sample.db", "field:DB.Header|ApplicationId", "0x00001234")
exp("sample.db", "field:DB.Header|SQLiteVersionNumber", str(sqver[0] * 1000000 + sqver[1] * 1000 + sqver[2]))


# ---------------------------------------------------------------- Unknown, empty, and truncated inputs
write("empty.bin", b"")
exp("empty.bin", "refined", "<none>")
exp("empty.bin", "meta.status", "NONE")
write("truncated_png_chunk.png", pn[:40])
exp("truncated_png_chunk.png", "meta.status", "EXTRACTION_FAILED")
bigchunk = bytearray(pn[:8]) + struct.pack(">I", 0xFFFFFFF0) + b"IDAT" + b"\x00" * 8
write("huge_png_chunk.png", bytes(bigchunk))
exp("huge_png_chunk.png", "meta.status", "EXTRACTION_FAILED")
write("bad_jpeg_segment.jpg", b"\xFF\xD8\xFF\xE0\x00\x01" + b"\x00" * 10)
exp("bad_jpeg_segment.jpg", "meta.status", "EXTRACTION_FAILED")

# OOXML with an external entity: must not be resolved.
xxe_core = b'''<?xml version="1.0"?><!DOCTYPE cp [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>&x;</dc:title></cp:coreProperties>'''
write("xxe.docx", zip_bytes([("[Content_Types].xml", CT), ("word/document.xml", b"<w/>"), ("docProps/core.xml", xxe_core)]))
exp("xxe.docx", "absent:OOXML.core|Title", "")

# Malformed OOXML properties XML.
write("bad_core.docx", zip_bytes([("[Content_Types].xml", CT), ("word/document.xml", b"<w/>"), ("docProps/core.xml", b"<cp:coreProperties><dc:title>oops")]))
exp("bad_core.docx", "error:docProps/core.xml", "")

with open(EXPECT_PATH, "w", encoding="utf-8", newline="\n") as f:
    f.write("file\tkey\tvalue\n")
    for file, key, value in expect:
        f.write(f"{file}\t{key}\t{value}\n")

print("fixtures:", len([f for f in os.listdir(OUT) if not f.endswith(".tsv")]), "expectations:", len(expect))
