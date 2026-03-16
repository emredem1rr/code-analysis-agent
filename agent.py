"""
Akıllı Kod Analiz Agentı v4.1 (Nihai Tam Otonom ve AST Destekli Sürüm)
=====================================================================
Güvenlik + Kalite odaklı, tamamen kendi karar veren kod analiz agentı.
AST tabanlı derin statik analiz, ReAct mimarisi ve Acımasız Yönetici içerir.

v4.0 → v4.1 Değişiklikler:
  + Regex tabanlı hardcoded secret scanner (7 pattern)
  + Raporu dosyaya otomatik kaydetme
  + import alias desteği (import pandas as pd)
  + Config dosya uzantıları genişletildi (.yml, .ini, .cfg, .toml)
  + Plaintext password comparison/storage tespiti
  + Dict içinde credential tespiti
  + Weak hash (MD5/SHA1) tespiti
  + os.system / subprocess shell=True tespiti
  + Path traversal tespiti
  + Tekrar eden döngü / duplicate fonksiyon tespiti
  + Dead code tespiti
  + Duplicate if/else bloğu düzeltildi

Kullanım: python agent.py
"""

import os
import sys
import json
import ast
import re
from collections import Counter
from datetime import datetime

# Windows konsol encoding düzeltmesi
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Ollama bağlantısı
try:
    from ollama import Client
except ImportError:
    print("HATA: 'ollama' kutuphanesi yuklu degil!")
    print("Cozum: pip install ollama")
    input("Kapatmak icin Enter'a basin...")
    sys.exit(1)

OLLAMA_MODEL = "llama3.2:3b"
OLLAMA_HOST = "http://localhost:11434"

try:
    client = Client(host=OLLAMA_HOST)
except Exception as e:
    print(f"HATA: Ollama'ya baglanilamiyor: {e}")
    print(f"Ollama'nin calistiginden emin olun: ollama serve")
    input("Kapatmak icin Enter'a basin...")
    sys.exit(1)

_reported_findings = set()

def _add_finding(file, line, rule_id, severity, short_title, explanation, code_snippet, recommendation):
    dedup_key = f"{file}:{line}:{rule_id}"
    if dedup_key in _reported_findings:
        return ""
    _reported_findings.add(dedup_key)
    sev_tr = {"HIGH": "YÜKSEK", "MEDIUM": "ORTA", "LOW": "DÜŞÜK"}.get(severity, severity)
    icon = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "⚪")
    return (
        f"  {icon} [{severity}] {short_title}\n"
        f"     Dosya: {file} | Satır: {line} | Kural: {rule_id} | Seviye: {sev_tr}\n"
        f"     Kod: {code_snippet[:120]}\n"
        f"     Açıklama: {explanation}\n"
        f"     Öneri: {recommendation}\n"
    )

def tum_islemler_tamamlandi_mi(proje_yolu, hafiza):
    """Tüm gerekli işlemlerin yapılıp yapılmadığını kontrol eder"""
    eksikler = []
    # [v4.1] Config uzantıları genişletildi
    CONFIG_EXTENSIONS = ('.json', '.yaml', '.yml', '.env', '.ini', '.cfg', '.toml')
    try:
        for item in os.listdir(proje_yolu):
            if item.startswith('rapor_'):
                continue  # Eski rapor dosyalarını atla
            item_yolu = os.path.join(proje_yolu, item)
            if os.path.isfile(item_yolu):
                if item.endswith('.py'):
                    if 'kod_analiz' not in hafiza.get(item, []):
                        eksikler.append(f"'{item}' için kod_analiz")
                    if 'guvenlik_tara' not in hafiza.get(item, []):
                        eksikler.append(f"'{item}' için guvenlik_tara")
                elif item.endswith(CONFIG_EXTENSIONS) or 'config' in item.lower():
                    if 'guvenlik_tara' not in hafiza.get(item, []):
                        eksikler.append(f"'{item}' için guvenlik_tara")
                elif item == 'requirements.txt':
                    if 'bagimlilik_kontrol' not in hafiza.get(item, []):
                        eksikler.append(f"'{item}' için bagimlilik_kontrol")
    except Exception as e:
        return [f"Hata: {e}"]
    return eksikler


# =====================================================================
# 1. AST TABANLI KALİTE VE GÜVENLİK SINIFLARI
# =====================================================================

class QualityAnalyzer(ast.NodeVisitor):
    def __init__(self, dosya_adi, lines):
        self.fn = dosya_adi
        self.lines = lines
        self.b = []
        self.current_func_depth = 0

    def visit_FunctionDef(self, node):
        self.current_func_depth += 1

        # 1. İç İçe Fonksiyon (Nested Function) Kontrolü
        if self.current_func_depth > 1:
            self.b.append(_add_finding(self.fn, node.lineno, "NESTED_FUNCTION", "LOW",
                "İç İçe Fonksiyon",
                "İç içe fonksiyonlar test edilebilirliği zorlaştırır.",
                f"def {node.name}(...):",
                "Fonksiyonu dışarı taşıyın veya OOP kullanın."))

        # 2. Çok Uzun Fonksiyon Kontrolü
        satir_sayisi = getattr(node, 'end_lineno', node.lineno) - node.lineno
        if satir_sayisi > 50:
            self.b.append(_add_finding(self.fn, node.lineno, "LONG_FUNCTION", "MEDIUM",
                f"Çok Uzun Fonksiyon ({satir_sayisi} satır)",
                f"Fonksiyon çok uzun ({satir_sayisi} satır). Okunabilirliği zor.",
                f"def {node.name}(...):",
                "Fonksiyonu Single Responsibility (SRP) ilkesine göre bölün."))
        elif satir_sayisi > 30:  # [v4.1] 30 satır eşiği eklendi
            self.b.append(_add_finding(self.fn, node.lineno, "LONG_FUNCTION", "LOW",
                f"Uzun Fonksiyon ({satir_sayisi} satır)",
                f"Fonksiyon {satir_sayisi} satır. 30 satırın altında tutulması önerilir.",
                f"def {node.name}(...):",
                "Fonksiyonu daha küçük parçalara ayırın."))

        # 3. Cyclomatic Complexity (Karmaşıklık) Kontrolü
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        if complexity > 10:
            self.b.append(_add_finding(self.fn, node.lineno, "HIGH_COMPLEXITY", "MEDIUM",
                f"Yüksek Karmaşıklık (CC={complexity})",
                "Kodda çok fazla dallanma (if/else/for) var.",
                f"def {node.name}(...):",
                "Erken dönüşler (early return) kullanın."))

        # 4. Docstring Kontrolü
        if not ast.get_docstring(node):
            self.b.append(_add_finding(self.fn, node.lineno, "MISSING_DOCSTRING", "LOW",
                f"Docstring Eksik: '{node.name}'",
                "Fonksiyonun ne işe yaradığını açıklayan yorum bloğu yok.",
                f"def {node.name}(...):",
                "Docstring ekleyin."))

        # [v4.1] 5. Tekrar Eden Döngü (Repeated Loop) Kontrolü
        loop_targets = []
        for child in ast.walk(node):
            if isinstance(child, ast.For) and isinstance(child.iter, ast.Name):
                loop_targets.append(child.iter.id)
        for target, count in Counter(loop_targets).items():
            if count >= 2:
                self.b.append(_add_finding(self.fn, node.lineno, "REPEATED_LOOP", "LOW",
                    f"Tekrar Eden Döngü: '{target}' ({count}x)",
                    f"'{node.name}' içinde '{target}' üzerinde {count} ayrı döngü var.",
                    f"for ... in {target}  # {count}x",
                    "Döngüleri birleştirin veya fonksiyonu parçalayın."))

        self.generic_visit(node)
        self.current_func_depth -= 1

    def visit_Global(self, node):
        # 6. Global Değişken Kullanımı
        self.b.append(_add_finding(self.fn, node.lineno, "GLOBAL_VARIABLE", "MEDIUM",
            "Global Değişken Kullanımı",
            "Global değişken kullanımı beklenmedik yan etkilere yol açar.",
            f"global {', '.join(node.names)}",
            "Sınıf yapıları veya parametre aktarımı kullanın."))
        self.generic_visit(node)

    def visit_ClassDef(self, node):  # [v4.1] Sınıf docstring kontrolü eklendi
        if not ast.get_docstring(node):
            self.b.append(_add_finding(self.fn, node.lineno, "MISSING_DOCSTRING", "LOW",
                f"Docstring Eksik: '{node.name}' sınıfı",
                "Sınıfın ne işe yaradığını açıklayan yorum bloğu yok.",
                f"class {node.name}:",
                "Docstring ekleyin."))
        self.generic_visit(node)


class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, dosya_adi, lines):
        self.fn = dosya_adi
        self.lines = lines
        self.b = []
        self.in_with_block = False

    def _extract_fstring_preview(self, node):
        """f-string'den önizleme metni çıkarır"""
        if isinstance(node, ast.JoinedStr):
            preview = ""
            for val in node.values[:2]:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    preview += val.value
                elif isinstance(val, ast.FormattedValue):
                    preview += "{...}"
            return preview
        return "f-string"

    def visit_With(self, node):
        self.in_with_block = True
        self.generic_visit(node)
        self.in_with_block = False

    def _get_name(self, node):
        """AST node'undan değişken adını çıkarmaya çalışır"""
        if isinstance(node, ast.Name): return node.id
        elif isinstance(node, ast.Attribute): return f"{self._get_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Subscript): return f"{self._get_name(node.value)}[{self._get_name(node.slice)}]"
        elif isinstance(node, ast.Call): return self._get_name(node.func)
        elif isinstance(node, ast.Constant): return str(node.value)
        elif isinstance(node, ast.List): return "list"
        elif isinstance(node, ast.Dict): return "dict"
        elif isinstance(node, ast.Tuple): return "tuple"
        else: return "unknown"

    def visit_Assign(self, node):
        """Değişken atamalarını kontrol et - SQL injection için"""
        if isinstance(node.value, ast.JoinedStr):
            for value in node.value.values:
                if isinstance(value, ast.FormattedValue):
                    var_name = self._get_name(value.value)
                    if var_name and 'sorgu' in self._get_name(node.targets[0]).lower():
                        self.b.append(_add_finding(
                            self.fn, node.lineno, "SQL_INJECTION", "HIGH",
                            "SQL Injection Riski (Hazırlık)",
                            "f-string ile SQL sorgusu oluşturuluyor.",
                            f"f'{self._extract_fstring_preview(node.value)}'...",
                            "Parametrik sorgu kullanın."))
        self.generic_visit(node)

    def visit_Call(self, node):
        # 7. Kaynak Sızıntısı ve Tehlikeli Fonksiyonlar
        if isinstance(node.func, ast.Name):
            if node.func.id == 'open' and not self.in_with_block:
                self.b.append(_add_finding(self.fn, node.lineno, "UNCLOSED_FILE", "MEDIUM",
                    "Açık Kalan Dosya (Kaynak Sızıntısı)",
                    "Dosya 'with' bloğu dışında açılmış. close() unutulabilir.",
                    "open(...)", "'with open(...) as f:' kullanın."))
            elif node.func.id == 'eval':
                self.b.append(_add_finding(self.fn, node.lineno, "EVAL_USAGE", "HIGH",
                    "eval() Kullanımı - RCE Riski",
                    "Dışarıdan gelen veriyle rastgele kod çalıştırılabilir.",
                    "eval(...)", "ast.literal_eval() kullanın."))
            elif node.func.id == 'exec':  # [v4.1] exec() eklendi
                self.b.append(_add_finding(self.fn, node.lineno, "EXEC_USAGE", "HIGH",
                    "exec() Kullanımı - RCE Riski",
                    "exec() rastgele kod çalıştırır.",
                    "exec(...)", "exec() kullanmayın."))

        # 8. SQL Injection, Pickle, os.system, subprocess
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ['execute', 'executemany', 'execute_query']:
                if node.args:
                    arg = node.args[0]
                    is_vuln = (
                        isinstance(arg, ast.JoinedStr) or
                        (isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Mod)) or
                        (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Attribute)
                         and arg.func.attr == 'format') or
                        (isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add))
                    )
                    if is_vuln:
                        self.b.append(_add_finding(
                            self.fn, node.lineno, "SQL_INJECTION", "HIGH",
                            "SQL Injection Riski",
                            "Kullanıcı girdisi doğrudan SQL sorgusuna ekleniyor.",
                            "execute(...)",
                            "Parametrik sorgu kullanın: cursor.execute('SELECT ... WHERE x = %s', (val,))"))

            # [v4.1] pickle.load() VE pickle.loads() tespiti
            elif (node.func.attr in ('load', 'loads')
                  and isinstance(node.func.value, ast.Name)
                  and node.func.value.id == 'pickle'):
                self.b.append(_add_finding(
                    self.fn, node.lineno, "PICKLE_USAGE", "HIGH",
                    "pickle.load() - RCE Riski",
                    "Güvensiz deserialization zafiyeti.",
                    "pickle.load(...)", "json modülünü kullanın."))

            # [v4.1] os.system() tespiti
            elif (node.func.attr == 'system' and isinstance(node.func.value, ast.Name)
                  and node.func.value.id == 'os'):
                self.b.append(_add_finding(
                    self.fn, node.lineno, "OS_SYSTEM", "HIGH",
                    "os.system() - Komut Enjeksiyonu Riski",
                    "Shell komutu çalıştırır, enjeksiyon riski taşır.",
                    "os.system(...)", "subprocess.run(shell=False) kullanın."))

            # [v4.1] subprocess shell=True tespiti
            elif node.func.attr in ['call', 'run', 'Popen', 'check_output']:
                for kw in node.keywords:
                    if (kw.arg == 'shell' and isinstance(kw.value, ast.Constant)
                            and kw.value.value is True):
                        self.b.append(_add_finding(
                            self.fn, node.lineno, "SUBPROCESS_SHELL", "HIGH",
                            "subprocess shell=True - Komut Enjeksiyonu",
                            "shell=True komut enjeksiyonuna açıktır.",
                            "subprocess(..., shell=True)",
                            "shell=False ve liste argümanları kullanın."))

        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if node.type is None:
            self.b.append(_add_finding(self.fn, node.lineno, "BARE_EXCEPT", "MEDIUM",
                "Bare except - Tüm Hatalar Yakalanıyor",
                "except: tüm exception'ları yakalar, hataları gizler.",
                "except:",
                "Spesifik exception tipi belirtin (except ValueError: vb.)"))
        self.generic_visit(node)


# =====================================================================
# [v4.1] REGEX TABANLI HARDCODED SECRET TARAYICI
# (AST'nin yanına ek — her iki yöntem birbirini tamamlar)
# =====================================================================

def regex_secret_scan(path, content, lines, filename):
    """
    İstenen 7 hardcoded secret pattern'ini + ek güvenlik kurallarını tarar.
    AST'nin yapısal olarak yakalayamadığı regex pattern'leri yakalar.
    """
    b = []
    is_py = path.endswith(".py")
    cl = content.lower()
    auth_ctx = any(k in cl for k in
                   ['login', 'auth', 'user', 'password', 'credential', 'db', 'database'])

    # ── 7 Zorunlu Secret Pattern ──────────────────────────────────
    SECRET_PATTERNS = [
        # 1. Username
        (r'(?i)(username|user)\s*[=:]\s*["\']?([^"\'\s]+)',
         "HARDCODED_USER", "Hardcoded Username", "MEDIUM"),
        # 2. Password
        (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]+)',
         "HARDCODED_PASSWORD", "Hardcoded Password", "MEDIUM"),
        # 3. API Key
        (r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([^"\'\s]+)',
         "HARDCODED_API_KEY", "Hardcoded API Key", "MEDIUM"),
        # 4. Secret / Token
        (r'(?i)(secret|token|jwt)\s*[=:]\s*["\']?([^"\'\s]+)',
         "HARDCODED_SECRET", "Hardcoded Secret/Token", "MEDIUM"),
        # 6. AWS Secret Key
        (r'(?i)(aws[_-]?secret[_-]?key)\s*[=:]\s*["\']?([^"\'\s]+)',
         "HARDCODED_AWS_SECRET", "Hardcoded AWS Secret Key", "HIGH"),
    ]

    for i, line in enumerate(lines, 1):
        s = line.strip()
        if s.startswith("#") or s.startswith("//"):
            continue

        # Secret pattern'leri tara
        for pattern, rule_id, title, severity in SECRET_PATTERNS:
            match = re.search(pattern, line)
            if match:
                var_name = match.group(1)
                value = match.group(2)
                # Placeholder / boş değerleri atla
                if value.lower() in ('none', 'null', 'todo', 'change_me', 'xxx',
                                     'your_key_here', '', 'true', 'false',
                                     'os.environ', 'os.getenv', 'environ'):
                    continue
                # os.environ.get() gibi güvenli kullanımları atla
                if 'os.environ' in line or 'os.getenv' in line:
                    continue
                b.append(_add_finding(filename, i, rule_id, severity,
                    f"{title}: '{var_name}'",
                    f"Gizli bilgi ('{var_name}') kaynak kodda açık metin olarak tutulmuş.",
                    s[:120], "Environment variable kullanın: os.environ.get()"))
                break  # Aynı satırda birden fazla match olmasın

        # 5. AWS Access Key ID (AKIA ile başlar)
        if re.search(r'AKIA[0-9A-Z]{16}', line):
            b.append(_add_finding(filename, i, "AWS_ACCESS_KEY", "HIGH",
                "AWS Access Key Tespit Edildi",
                "AWS Access Key ID kaynak kodda açık. Hesap ele geçirilebilir.",
                s[:120], "AWS Secrets Manager veya env variable kullanın."))

        # 7. DEBUG=True
        if re.search(r'DEBUG\s*=\s*True', line):
            b.append(_add_finding(filename, i, "DEBUG_ENABLED", "MEDIUM",
                "DEBUG=True - Üretimde Güvensiz",
                "Debug modu üretim ortamında açık bırakılmış. Hassas bilgiler sızabilir.",
                s[:120], "Üretim ortamında DEBUG=False yapın."))

    # ── Ek Güvenlik Kuralları ─────────────────────────────────────

    # Plaintext Password Comparison (==, !=)
    if is_py:
        pw_re = r'\b\w*(password|passwd|pwd|pass)\w*\b'
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            if re.search(pw_re, line, re.IGNORECASE):
                if '==' in line and not re.match(r'^\w+\s*=\s*[^=]', s):
                    b.append(_add_finding(filename, i, "PLAINTEXT_PW_CMP", "MEDIUM",
                        "Plaintext Şifre Karşılaştırması (==)",
                        "Şifre düz metin karşılaştırılıyor.",
                        s[:120], "bcrypt.checkpw() kullanın."))
                if '!=' in line and not re.match(r'^\w+\s*=\s*[^=]', s):
                    b.append(_add_finding(filename, i, "PLAINTEXT_PW_CMP_NE", "MEDIUM",
                        "Plaintext Şifre Karşılaştırması (!=)",
                        "Şifre düz metin karşılaştırılıyor.",
                        s[:120], "Hash tabanlı karşılaştırma kullanın."))

    # Weak Hash (MD5, SHA1)
    if is_py:
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            if re.search(r'hashlib\.md5\s*\(', line):
                b.append(_add_finding(filename, i, "WEAK_HASH_MD5", "MEDIUM",
                    "MD5 - Güvensiz Hash",
                    "MD5 kriptografik olarak kırılmıştır.",
                    s[:120], "bcrypt veya argon2 kullanın."))
            if re.search(r'hashlib\.sha1\s*\(', line):
                b.append(_add_finding(filename, i, "WEAK_HASH_SHA1", "MEDIUM",
                    "SHA1 - Güvensiz Hash",
                    "SHA1 kriptografik olarak kırılmıştır.",
                    s[:120], "bcrypt veya argon2 kullanın."))

    # Unsafe File Access / Path Traversal
    if is_py:
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            om = re.search(r'open\s*\(\s*(\w+)', line)
            if om:
                var = om.group(1)
                for risky in ['path', 'file', 'user', 'input', 'filename', 'filepath']:
                    if risky in var.lower():
                        b.append(_add_finding(filename, i, "UNSAFE_FILE_ACCESS", "HIGH",
                            f"Path Traversal Riski: open({var})",
                            "Kullanıcı kontrollü değişkenle dosya açmak path traversal riski.",
                            s[:120], "os.path.realpath() + whitelist kullanın."))
                        break

    # Dict İçinde Credential
    if is_py and auth_ctx:
        dp = re.compile(r'["\'](\w+)["\']\s*:\s*["\']([^"\']+)["\']')
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith("#"):
                continue
            for key, val in dp.findall(line):
                pw_like = (re.match(r'^[a-zA-Z0-9_!@#$%^&*]+$', val)
                           and len(val) >= 4 and len(val) <= 30
                           and any(c.isdigit() for c in val)
                           and val not in ('true', 'false', 'null', 'none', 'localhost', 'utf-8'))
                user_keys = ['admin', 'user', 'root', 'guest', 'operator', 'manager']
                is_user_key = any(u in key.lower() for u in user_keys) or re.match(r'^[a-z]{2,15}$', key)
                if pw_like and is_user_key:
                    b.append(_add_finding(filename, i, "HARDCODED_CRED_DICT", "MEDIUM",
                        f"Dict'te Credential: '{key}':'{val}'",
                        "Kullanıcı/parola dict'te açık metin.",
                        s[:120], "DB ve hash'lenmiş şifreler kullanın."))
                    b.append(_add_finding(filename, i, "PLAINTEXT_PW_DICT", "MEDIUM",
                        f"Dict'te Plaintext Parola: '{val}'",
                        "Şifre hash'siz saklanıyor.",
                        s[:120], "bcrypt/argon2 ile hash'leyin."))

    # Plaintext Password Storage (hash yoksa)
    if is_py:
        has_secure = any(k in cl for k in ['bcrypt', 'argon2', 'pbkdf2', 'scrypt'])
        if not has_secure:
            for i, line in enumerate(lines, 1):
                s = line.strip()
                if s.startswith("#"):
                    continue
                m = re.search(
                    r'\b(\w*(password|passwd|pwd)\w*)\s*=\s*["\']([^"\']+)["\']',
                    line, re.IGNORECASE)
                if m:
                    b.append(_add_finding(filename, i, "PLAINTEXT_PW_STORE", "MEDIUM",
                        f"Plaintext Parola Depolama: '{m.group(1)}'",
                        "Şifre hash'siz saklanıyor.",
                        s[:120], "bcrypt.hashpw() ile hash'leyin."))

    return b


# =====================================================================
# 2. ARAÇLAR (TOOLS) — mevcut yapı korundu, sadece ekleme yapıldı
# =====================================================================

def klasor_listele(path):
    try:
        items = []
        for item in sorted(os.listdir(path)):
            fp = os.path.join(path, item)
            if os.path.isdir(fp):
                items.append(f"📁 {item}/")
            else:
                items.append(f"📄 {item} ({os.path.getsize(fp)} byte)")
        return "\n".join(items) if items else "Klasör boş."
    except Exception as e:
        return f"Hata: {e}"


def dosya_oku(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            c = f.read()
        return c[:3000] + "\n..." if len(c) > 3000 else c
    except Exception as e:
        return f"Hata: {e}"


def kod_analiz(path):
    if not path.endswith(".py"):
        return f"⚠️ ATLANDI: '{path}' Python dosyası değil."
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return f"Hata: {e}"

    fn = os.path.basename(path)
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        return f"⚠️ SYNTAX HATASI: {e}"

    lines = content.split("\n")
    analyzer = QualityAnalyzer(fn, lines)
    analyzer.visit(tree)

    # [v4.1] Kullanılmayan Import — alias desteği ile (import pandas as pd düzeltmesi)
    import_names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                search_name = alias.asname or alias.name
                import_names[search_name] = (alias.name, node.lineno)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                search_name = alias.asname or alias.name
                import_names[search_name] = (alias.name, node.lineno)

    for search_name, (orig, lineno) in import_names.items():
        # Tam kelime eşleşmesi, import satırlarını hariç tut
        usage = 0
        for j, l in enumerate(lines):
            ls = l.strip()
            if ls.startswith("import ") or ls.startswith("from "):
                continue
            if re.search(rf'\b{re.escape(search_name)}\b', l):
                usage += 1
        if usage == 0:
            display = f"'{orig}'" if orig == search_name else f"'{orig}' (as {search_name})"
            analyzer.b.append(_add_finding(fn, lineno, "UNUSED_IMPORT", "LOW",
                f"Kullanılmayan Import: {display}",
                f"{display} import edilmiş ama kodda hiç kullanılmıyor.",
                lines[lineno - 1].strip() if lineno <= len(lines) else f"import {orig}",
                "Kullanılmayan import'ları kaldırın."))

    # [v4.1] Duplicate function tespiti
    func_sigs = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            try:
                body = ast.dump(node)
                norm = re.sub(r"arg='[^']*'", "arg='X'", body)
                norm = re.sub(r"id='[^']*'", "id='X'", norm)
                norm = re.sub(r"name='[^']*'", "name='F'", norm)
                func_sigs.append((node.name, node.lineno, norm))
            except:
                pass

    reported_pairs = set()
    for i_idx, (n1, l1, h1) in enumerate(func_sigs):
        for j_idx, (n2, l2, h2) in enumerate(func_sigs):
            if i_idx >= j_idx:
                continue
            if h1 == h2:
                pair = tuple(sorted([n1, n2]))
                if pair not in reported_pairs:
                    reported_pairs.add(pair)
                    analyzer.b.append(_add_finding(fn, l2, "DUPLICATE_FUNCTION", "MEDIUM",
                        f"Tekrar Eden Fonksiyon: '{n1}' ≈ '{n2}'",
                        f"'{n1}' (satır {l1}) ile '{n2}' (satır {l2}) yapısal olarak aynı.",
                        f"def {n1}(...) ≈ def {n2}(...)",
                        "Ortak fonksiyon yazıp tekrarı kaldırın (DRY prensibi)."))

    # [v4.1] Dead code (sadece pass)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                analyzer.b.append(_add_finding(fn, node.lineno, "DEAD_CODE", "LOW",
                    f"Boş Fonksiyon: '{node.name}'",
                    f"'{node.name}' fonksiyonu sadece 'pass' içeriyor.",
                    f"def {node.name}(...): pass",
                    "Fonksiyonu implement edin veya kaldırın."))

    # Metrikler
    total = len(lines)
    empty = sum(1 for l in lines if l.strip() == "")
    comm = sum(1 for l in lines if l.strip().startswith("#"))
    metrik = f"\n  📊 Metrikler ({fn}): {total} satır | {empty} boş | {comm} yorum | {total-empty-comm} kod"

    findings = [x for x in analyzer.b if x]
    if not findings:
        return f"✅ {fn}: Kod kalitesi sorunu bulunamadı." + metrik
    return f"📝 KOD ANALİZİ: {fn}\n" + "\n".join(findings) + metrik


def guvenlik_tara(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        return f"Hata: {e}"

    fn = os.path.basename(path)
    lines = content.split("\n")
    b = []

    if path.endswith(".py"):
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return f"⚠️ SYNTAX HATASI: {fn}"

        # AST tabanlı analiz (mevcut)
        analyzer = SecurityAnalyzer(fn, lines)
        analyzer.visit(tree)
        b.extend(analyzer.b)

        # [v4.1] Regex tabanlı analiz (AST'yi tamamlar)
        b.extend(regex_secret_scan(path, content, lines, fn))
    else:
        # JSON, YAML, ENV gibi config dosyaları için
        secret_kw = ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'CREDENTIAL',
                     'API_KEY', 'AWS', 'AUTH', 'PRIVATE']
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("//"):
                continue
            for kw in secret_kw:
                if kw in line.upper():
                    if '=' in line or ':' in line:
                        val_match = re.search(r'[=:]\s*["\']?([^"\'}\],\s]+)', line)
                        if val_match and len(val_match.group(1)) > 3:
                            b.append(_add_finding(fn, i, "CONFIG_SECRET", "MEDIUM",
                                f"Config Secret: '{kw}'",
                                "Gizli bilgi ayar dosyasında düz metin.",
                                s[:120], "Environment variable kullanın."))
                            break

            # [v4.1] Credential benzeri değer (sk-, AKIA, ghp_ vb.)
            val_match = re.search(r'["\']([^"\']{8,})["\']', line)
            if val_match:
                val = val_match.group(1)
                if re.match(r'^(sk[-_]|pk[-_]|AKIA|ghp_|gho_|xox[bpsa]-)', val):
                    b.append(_add_finding(fn, i, "CONFIG_SECRET_VALUE", "MEDIUM",
                        "Credential Benzeri Değer",
                        "Bu string bir API key veya token olabilir.",
                        s[:120], "Environment variable kullanın."))

    findings = [x for x in b if x]
    if not findings:
        return f"✅ {fn}: Güvenlik sorunu bulunamadı."
    h = sum(1 for x in findings if "[HIGH]" in x)
    m = sum(1 for x in findings if "[MEDIUM]" in x)
    l = sum(1 for x in findings if "[LOW]" in x)
    return f"🔒 GÜVENLİK TARAMASI: {fn}\n" + "\n".join(findings) + f"\n  📊 Özet: {h} high, {m} medium, {l} low"


def bagimlilik_kontrol(path):
    if path.endswith(".py") or path.endswith(".json"):
        return "❌ HATA: 'bagimlilik_kontrol' aracı Python (.py) veya JSON dosyalarında KULLANILAMAZ."
    rp = path if not os.path.isdir(path) else os.path.join(path, "requirements.txt")
    if not os.path.exists(rp):
        return "❌ requirements.txt bulunamadı!"
    with open(rp, encoding="utf-8") as f:
        raw = f.read().strip().split("\n")

    fn = os.path.basename(rp)

    VULNERABILITY_DB = {
        "pickle5": {"risk": "HIGH", "aciklama": "Güvensiz deserialization zafiyeti (CVE-202X).", "cozum": "Kullanımdan kaldırın."},
        "django": {"max_safe": "3.2.0", "risk": "HIGH", "aciklama": "Django < 3.2 SQLi zafiyeti barındırır.", "cozum": "Güncelleyin."},
        "requests": {"max_safe": "2.20.0", "risk": "MEDIUM", "aciklama": "Requests < 2.20 CVE-2018-18074 zafiyeti.", "cozum": "Güncelleyin."},
        "flask": {"max_safe": "2.0.0", "risk": "MEDIUM", "aciklama": "Flask < 2.0 oturum güvenliği sorunları.", "cozum": "Güncelleyin."},
        "pyyaml": {"max_safe": "5.0.0", "risk": "HIGH", "aciklama": "PyYAML < 5.0 CVE-2017-18342 RCE.", "cozum": "Güncelleyin."},
        "cryptography": {"max_safe": "3.0.0", "risk": "MEDIUM", "aciklama": "cryptography < 3.0 eski algoritmalar.", "cozum": "Güncelleyin."},
        "pillow": {"max_safe": "9.0.0", "risk": "MEDIUM", "aciklama": "Pillow < 9.0 buffer overflow.", "cozum": "Güncelleyin."},
    }

    b, info = [], []
    for ln, r_line in enumerate(raw, 1):
        d = r_line.strip()
        if not d or d.startswith("#"):
            continue
        pkg_name = d.split('==')[0].split('>=')[0].split('<=')[0].strip().lower()

        if "==" not in d and ">=" not in d:
            b.append(_add_finding(fn, ln, "UNPINNED_DEP", "MEDIUM",
                f"Sabitlenmemiş Paket: '{d}'",
                "Zafiyetli alt versiyon otomatik yüklenebilir.",
                d, "== ile versiyon sabitleyin."))
            info.append(f"  ⚠️ {d}")
        else:
            info.append(f"  ✅ {d}")

        if pkg_name in VULNERABILITY_DB:
            vuln = VULNERABILITY_DB[pkg_name]
            if "max_safe" not in vuln:
                b.append(_add_finding(fn, ln, "VULNERABLE_PKG", vuln["risk"],
                    f"Tehlikeli Paket: {pkg_name}", vuln["aciklama"], d, vuln["cozum"]))
            elif "==" in d:
                version = d.split("==")[1].strip()
                if version < vuln["max_safe"]:
                    b.append(_add_finding(fn, ln, "VULNERABLE_VER", vuln["risk"],
                        f"Eski Zafiyetli Versiyon: {pkg_name}", vuln["aciklama"], d, vuln["cozum"]))

    findings = [x for x in b if x]
    res = f"📦 BAĞIMLILIK ANALİZİ ({len(raw)} paket):\n" + "\n".join(info)
    if findings:
        res += "\n\n  Bulgular:\n" + "\n".join(findings)
    return res


# =====================================================================
# RAPOR + DOSYAYA KAYDETME
# =====================================================================

def rapor_olustur(bl):
    r = "\n" + "=" * 60 + "\n📋 KOD ANALİZ RAPORU v4.1 (AST + REGEX DESTEKLİ)\n" + "=" * 60 + "\n\n"
    seen = set()
    all_findings = []
    for entry in bl:
        for line in entry.split("\n"):
            stripped = line.strip()
            m = re.search(r'Dosya:\s*(\S+)\s*\|\s*Satır:\s*(\d+)\s*\|\s*Kural:\s*(\S+)', stripped)
            if m:
                dedup = (m.group(1), m.group(2), m.group(3))
                if dedup in seen:
                    continue
                seen.add(dedup)
            if stripped.startswith("🔴") or stripped.startswith("🟡") or stripped.startswith("🔵"):
                all_findings.append(stripped)
            elif any(stripped.startswith(p) for p in ["Dosya:", "Kod:", "Açıklama:", "Öneri:"]):
                if all_findings:
                    all_findings[-1] += "\n     " + stripped

    h = [f for f in all_findings if "[HIGH]" in f]
    m_list = [f for f in all_findings if "[MEDIUM]" in f]
    l = [f for f in all_findings if "[LOW]" in f]

    if h:
        r += f"🔴 YÜKSEK SEVİYE ({len(h)}):\n" + "-" * 50 + "\n"
        r += "\n\n".join(f"  {f}" for f in h) + "\n\n"
    if m_list:
        r += f"🟡 ORTA SEVİYE ({len(m_list)}):\n" + "-" * 50 + "\n"
        r += "\n\n".join(f"  {f}" for f in m_list) + "\n\n"
    if l:
        r += f"🔵 DÜŞÜK SEVİYE ({len(l)}):\n" + "-" * 50 + "\n"
        r += "\n\n".join(f"  {f}" for f in l) + "\n\n"

    r += "=" * 60
    r += f"\nTOPLAM: {len(h)} yüksek | {len(m_list)} orta | {len(l)} düşük\n"
    r += f"Toplam tekil bulgu: {len(h) + len(m_list) + len(l)}\n"
    r += "=" * 60 + "\n"
    return r


def rapor_kaydet(rapor_metni, proje_yolu):
    """Raporu profesyonel PDF formatında kaydeder."""
    tarih = datetime.now().strftime("%Y%m%d_%H%M%S")
    tarih_gosterim = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
    dosya_adi = os.path.join(proje_yolu, f"rapor_{tarih}.pdf")

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, black, white
        from reportlab.lib.units import mm, cm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            PageBreak, HRFlowable
        )

        doc = SimpleDocTemplate(
            dosya_adi, pagesize=A4,
            topMargin=2*cm, bottomMargin=2*cm,
            leftMargin=2*cm, rightMargin=2*cm
        )

        # Türkçe karakter desteği için DejaVu Sans fontunu kaydet
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        # Sistemde DejaVu Sans fontunu bul
        font_paths = [
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
        ]
        # Matplotlib ile gelen yedek yol
        try:
            import matplotlib
            mpl_font = os.path.join(os.path.dirname(matplotlib.__file__),
                                     "mpl-data", "fonts", "ttf", "DejaVuSans.ttf")
            mpl_bold = os.path.join(os.path.dirname(matplotlib.__file__),
                                     "mpl-data", "fonts", "ttf", "DejaVuSans-Bold.ttf")
            mpl_oblique = os.path.join(os.path.dirname(matplotlib.__file__),
                                        "mpl-data", "fonts", "ttf", "DejaVuSans-Oblique.ttf")
            font_paths = [mpl_font, mpl_bold, mpl_oblique] + font_paths
        except ImportError:
            pass

        # İlk bulunan DejaVu fontlarını kaydet
        FONT_NORMAL = 'Helvetica'
        FONT_BOLD = 'Helvetica-Bold'
        FONT_ITALIC = 'Helvetica-Oblique'

        for fp in font_paths:
            if os.path.exists(fp) and 'Bold' not in fp and 'Oblique' not in fp:
                try:
                    pdfmetrics.registerFont(TTFont('DejaVu', fp))
                    FONT_NORMAL = 'DejaVu'
                    break
                except:
                    pass
        for fp in font_paths:
            if os.path.exists(fp) and 'Bold' in fp:
                try:
                    pdfmetrics.registerFont(TTFont('DejaVuBd', fp))
                    FONT_BOLD = 'DejaVuBd'
                    break
                except:
                    pass
        for fp in font_paths:
            if os.path.exists(fp) and 'Oblique' in fp:
                try:
                    pdfmetrics.registerFont(TTFont('DejaVuIt', fp))
                    FONT_ITALIC = 'DejaVuIt'
                    break
                except:
                    pass
        styles = getSampleStyleSheet()
        story = []

        # Renkler
        RED = HexColor("#e74c3c")
        ORANGE = HexColor("#f39c12")
        BLUE = HexColor("#3498db")
        DARK = HexColor("#2c3e50")
        LIGHT_RED = HexColor("#fdecea")
        LIGHT_ORANGE = HexColor("#fef9e7")
        LIGHT_BLUE = HexColor("#eaf2f8")
        GRAY = HexColor("#95a5a6")
        WHITE = HexColor("#ffffff")

        # Özel stiller (Türkçe uyumlu fontlarla)
        styles.add(ParagraphStyle('RaporBaslik',
            parent=styles['Title'], fontSize=22, textColor=DARK,
            fontName=FONT_BOLD, spaceAfter=6, alignment=TA_CENTER))
        styles.add(ParagraphStyle('AltBaslik',
            parent=styles['Normal'], fontSize=11, textColor=GRAY,
            fontName=FONT_NORMAL, alignment=TA_CENTER, spaceAfter=20))
        styles.add(ParagraphStyle('SeviyeBaslik',
            parent=styles['Heading2'], fontSize=14, textColor=DARK,
            fontName=FONT_BOLD, spaceBefore=16, spaceAfter=8))
        styles.add(ParagraphStyle('BulguBaslik',
            parent=styles['Normal'], fontSize=10, textColor=DARK,
            fontName=FONT_BOLD, spaceBefore=6, spaceAfter=2))
        styles.add(ParagraphStyle('BulguDetay',
            parent=styles['Normal'], fontSize=8, textColor=HexColor("#555555"),
            fontName=FONT_NORMAL, leftIndent=12, spaceAfter=1))
        styles.add(ParagraphStyle('KodStil',
            parent=styles['Normal'], fontSize=8, textColor=HexColor("#c0392b"),
            fontName='Courier', leftIndent=12, spaceAfter=1))
        styles.add(ParagraphStyle('OneriStil',
            parent=styles['Normal'], fontSize=8, textColor=HexColor("#27ae60"),
            fontName=FONT_ITALIC, leftIndent=12, spaceAfter=8))

        # === KAPAK ===
        story.append(Spacer(1, 60))
        story.append(Paragraph("KOD ANALIZ RAPORU", styles['RaporBaslik']))
        story.append(Paragraph("v4.1 | AST + Regex Tabanli Derin Statik Analiz", styles['AltBaslik']))
        story.append(HRFlowable(width="80%", thickness=2, color=DARK, spaceAfter=20))

        # Proje bilgisi tablosu
        proje_adi = os.path.basename(os.path.abspath(proje_yolu))
        bilgi_data = [
            ["Proje", proje_adi],
            ["Tarih", tarih_gosterim],
            ["Arac", "Otonom Kod Analiz Agenti v4.1"],
            ["Model", OLLAMA_MODEL],
        ]
        bilgi_tablo = Table(bilgi_data, colWidths=[4*cm, 10*cm])
        bilgi_tablo.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), FONT_BOLD),
            ('FONTNAME', (1, 0), (1, -1), FONT_NORMAL),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (0, -1), DARK),
            ('TEXTCOLOR', (1, 0), (1, -1), HexColor("#555555")),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ]))
        story.append(bilgi_tablo)
        story.append(Spacer(1, 30))

        # === BULGULARI PARSE ET ===
        rapor_satirlari = rapor_metni.split("\n")
        high_count = rapor_metni.count("[HIGH]")
        med_count = rapor_metni.count("[MEDIUM]")
        low_count = rapor_metni.count("[LOW]")
        total = high_count + med_count + low_count

        # Özet tablosu
        ozet_data = [
            ["Seviye", "Adet"],
            ["YUKSEK (HIGH)", str(high_count)],
            ["ORTA (MEDIUM)", str(med_count)],
            ["DUSUK (LOW)", str(low_count)],
            ["TOPLAM", str(total)],
        ]
        ozet_tablo = Table(ozet_data, colWidths=[8*cm, 4*cm])
        ozet_tablo.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, 0), FONT_BOLD),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('BACKGROUND', (0, 0), (-1, 0), DARK),
            ('TEXTCOLOR', (0, 0), (-1, 0), WHITE),
            ('BACKGROUND', (0, 1), (-1, 1), LIGHT_RED),
            ('TEXTCOLOR', (0, 1), (-1, 1), RED),
            ('BACKGROUND', (0, 2), (-1, 2), LIGHT_ORANGE),
            ('TEXTCOLOR', (0, 2), (-1, 2), ORANGE),
            ('BACKGROUND', (0, 3), (-1, 3), LIGHT_BLUE),
            ('TEXTCOLOR', (0, 3), (-1, 3), BLUE),
            ('FONTNAME', (0, 4), (-1, 4), FONT_BOLD),
            ('BACKGROUND', (0, 4), (-1, 4), HexColor("#ecf0f1")),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor("#bdc3c7")),
        ]))
        story.append(ozet_tablo)
        story.append(PageBreak())

        # === BULGULAR ===
        def bulgu_ekle(bulgular, seviye_adi, renk, bg_renk):
            if not bulgular:
                return
            story.append(Paragraph(f"{seviye_adi} ({len(bulgular)} bulgu)", styles['SeviyeBaslik']))
            story.append(HRFlowable(width="100%", thickness=1, color=renk, spaceAfter=8))

            for bulgu in bulgular:
                satirlar = bulgu.split("\n")
                baslik = satirlar[0] if satirlar else bulgu
                # Emoji'leri temizle
                baslik_clean = baslik.replace("[HIGH]", "").replace("[MEDIUM]", "").replace("[LOW]", "").strip()
                for ch in ['🔴', '🟡', '🔵', '⚪']:
                    baslik_clean = baslik_clean.replace(ch, "").strip()

                story.append(Paragraph(f"[!] {baslik_clean}", styles['BulguBaslik']))

                for satir in satirlar[1:]:
                    s = satir.strip()
                    if s.startswith("Dosya:"):
                        story.append(Paragraph(s, styles['BulguDetay']))
                    elif s.startswith("Kod:"):
                        story.append(Paragraph(s, styles['KodStil']))
                    elif s.startswith("Aciklama:") or s.startswith("Açıklama:"):
                        s_clean = s.replace("Açıklama:", "Aciklama:")
                        story.append(Paragraph(s_clean, styles['BulguDetay']))
                    elif s.startswith("Oneri:") or s.startswith("Öneri:"):
                        s_clean = s.replace("Öneri:", "Oneri:")
                        story.append(Paragraph(s_clean, styles['OneriStil']))

        # Bulguları ayır
        all_findings = []
        for line in rapor_satirlari:
            s = line.strip()
            if any(s.startswith(ch) for ch in ['🔴', '🟡', '🔵']):
                all_findings.append(s)
            elif any(s.startswith(p) for p in ["Dosya:", "Kod:", "Açıklama:", "Öneri:"]):
                if all_findings:
                    all_findings[-1] += "\n" + s

        h_list = [f for f in all_findings if "[HIGH]" in f]
        m_list = [f for f in all_findings if "[MEDIUM]" in f]
        l_list = [f for f in all_findings if "[LOW]" in f]

        bulgu_ekle(h_list, "YUKSEK SEVIYE BULGULAR", RED, LIGHT_RED)
        bulgu_ekle(m_list, "ORTA SEVIYE BULGULAR", ORANGE, LIGHT_ORANGE)
        bulgu_ekle(l_list, "DUSUK SEVIYE BULGULAR", BLUE, LIGHT_BLUE)

        # Alt bilgi
        story.append(Spacer(1, 30))
        story.append(HRFlowable(width="100%", thickness=1, color=GRAY, spaceAfter=10))
        story.append(Paragraph(
            f"Bu rapor Otonom Kod Analiz Agenti v4.1 tarafindan otomatik olusturulmustur. | {tarih_gosterim}",
            ParagraphStyle('Footer', parent=styles['Normal'], fontSize=8,
                          textColor=GRAY, alignment=TA_CENTER, fontName=FONT_NORMAL)
        ))

        # PDF oluştur
        doc.build(story)
        print(f"\n💾 Rapor PDF olarak kaydedildi: {dosya_adi}")
        return dosya_adi

    except ImportError:
        # reportlab yoksa txt olarak kaydet
        print("⚠️ reportlab yüklü değil, TXT olarak kaydediliyor...")
        txt_dosya = os.path.join(proje_yolu, f"rapor_{tarih}.txt")
        with open(txt_dosya, "w", encoding="utf-8") as f:
            f.write(rapor_metni)
        print(f"\n💾 Rapor TXT olarak kaydedildi: {txt_dosya}")
        return txt_dosya
    except Exception as e:
        print(f"⚠️ Rapor kaydetme hatası: {e}")
        return None


# =====================================================================
# 3. YAPAY ZEKA (AGENT) BEYNİ — mevcut yapı korundu
# =====================================================================

TOOLS = {
    "klasor_listele": {"func": klasor_listele, "description": "Dizindeki dosyaları listeler. Parametre: klasör yolu (örn: ./)"},
    "dosya_oku": {"func": dosya_oku, "description": "Dosya içeriğini okur. Parametre: dosya adı"},
    "kod_analiz": {"func": kod_analiz, "description": "SADECE .py dosyalarının kalitesini analiz eder. Parametre: dosya adı"},
    "bagimlilik_kontrol": {"func": bagimlilik_kontrol, "description": "requirements.txt analiz eder. Parametre: dosya adı"},
    "guvenlik_tara": {"func": guvenlik_tara, "description": "Tüm dosya tiplerinde (.py, .json, .yaml, .env) güvenlik açığı arar. Parametre: dosya adı"},
}

SYSTEM_PROMPT = """You are a Code Analysis Agent. You analyze projects step by step.

TOOLS: klasor_listele, dosya_oku, kod_analiz, guvenlik_tara, bagimlilik_kontrol

HOW TO ANALYZE:
1. klasor_listele to see files
2. For each .py file → kod_analiz, then guvenlik_tara (2 separate calls)
3. For each .json/.yaml/.env file → guvenlik_tara only
4. For requirements.txt → bagimlilik_kontrol only
5. DONE only when PENDING list is empty

IMPORTANT RULES:
- ONE file per call. Never combine files.
- Check PENDING list. If PENDING has items, do NOT say DONE.
- ONLY say DONE when PENDING says "(none - all done!)"
- After finishing one file, move to the NEXT file in PENDING list.
- Params = single filename like: auth.py

FORMAT (exactly 3 lines only):
Thought: ...
Action: ...
Params: ...

EXAMPLE with 3 files (app.py, config.json, requirements.txt):

Thought: First I list files
Action: klasor_listele
Params: ./project

Thought: app.py needs kod_analiz
Action: kod_analiz
Params: app.py

Thought: app.py also needs guvenlik_tara
Action: guvenlik_tara
Params: app.py

Thought: config.json needs guvenlik_tara
Action: guvenlik_tara
Params: config.json

Thought: requirements.txt needs bagimlilik_kontrol
Action: bagimlilik_kontrol
Params: requirements.txt

Thought: PENDING is empty, all files done
Action: DONE
Params: none
"""


def parse_agent_response(resp):
    thought, action, params = "", "", ""
    for line in resp.strip().split("\n"):
        l = line.strip()
        if l.startswith("Thought:") and not thought:
            thought = l[8:].strip()
        elif l.startswith("Action:") and not action:
            raw_action = l[7:].strip()
            # Tool ismindeki boşlukları underscore'a çevir ("kod analiz" → "kod_analiz")
            # İlk kelimeden sonra hâlâ tool ismi olabilir
            first_word = raw_action.split()[0] if raw_action.split() else raw_action
            if first_word not in TOOLS and first_word.upper() != "DONE":
                # "kod analiz" → "kod_analiz", "klasör listele" → "klasor_listele"
                candidate = raw_action.split("(")[0].strip().replace(" ", "_").replace("ö", "o").replace("ü", "u")
                if candidate in TOOLS:
                    action = candidate
                else:
                    action = first_word
            else:
                action = first_word
        elif l.startswith("Params:") and not params:
            raw_params = l[7:].strip()
            if "(" in raw_params:
                raw_params = raw_params.split("(")[0].strip()
            raw_params = raw_params.strip('"').strip("'")
            # Virgülle birden fazla dosya verilmişse sadece ilkini al
            if "," in raw_params:
                raw_params = raw_params.split(",")[0].strip()
            if " " in raw_params and not raw_params.startswith("./"):
                raw_params = raw_params.split()[0]
            params = raw_params if raw_params.lower() != "none" else ""
    return thought, action, params, action.upper() == "DONE"


def execute_tool(action, params, pp):
    if action not in TOOLS:
        return f"HATA: '{action}' geçersiz bir araç."
    if not params or params.strip().lower() == "none":
        p = pp
    else:
        p = params.strip()
        if " " in p and not p.startswith("./"):
            p = p.split()[0]
        if not os.path.isabs(p) and not p.startswith("./"):
            p = os.path.join(pp, p)

    # Analiz araçlarının klasöre uygulanmasını engelle (klasor_listele hariç)
    if action in ("kod_analiz", "guvenlik_tara") and os.path.isdir(p):
        return (f"HATA: '{action}' bir KLASÖRE uygulanamaz! "
                f"TEK BİR DOSYA adı ver. Örnek: {action} auth.py")

    # bagimlilik_kontrol her zaman proje klasörünü kullansın
    if action == "bagimlilik_kontrol":
        p = pp

    return TOOLS[action]["func"](p)


def run_agent(pp, max_steps=25):
    global _reported_findings
    _reported_findings = set()
    bl = []
    af = {}

    print("\n" + "=" * 60 + "\n🤖 OTONOM KOD ANALİZ AGENTI v4.1 (AST + REGEX DESTEKLİ)\n" + "=" * 60)
    print(f"📂 Proje: {pp}\n⚙️ Model: {OLLAMA_MODEL}\n🔄 Max adım: {max_steps}\n" + "=" * 60)

    # Proje dosyalarını önceden tara
    all_project_files = []
    CONFIG_EXT = ('.json', '.yaml', '.yml', '.env', '.ini', '.cfg', '.toml')
    try:
        for item in sorted(os.listdir(pp)):
            if item.startswith('rapor_'):
                continue  # Eski rapor dosyalarını atla
            if os.path.isfile(os.path.join(pp, item)):
                all_project_files.append(item)
    except:
        pass

    def get_next_task():
        """SADECE agent hata yaptığında kurtarma amaçlı kullanılır."""
        for f in all_project_files:
            if f.endswith(".py"):
                if "kod_analiz" not in af.get(f, []):
                    return "kod_analiz", f
                if "guvenlik_tara" not in af.get(f, []):
                    return "guvenlik_tara", f
            elif f.endswith(CONFIG_EXT) or 'config' in f.lower():
                if "guvenlik_tara" not in af.get(f, []):
                    return "guvenlik_tara", f
        if "requirements.txt" in all_project_files:
            if not any("bagimlilik_kontrol" in t for t in af.values()):
                return "bagimlilik_kontrol", "requirements.txt"
        return None, None

    consecutive_errors = 0  # Arka arkaya hata sayacı

    msgs = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": f"Görev Başlangıcı. Analiz edilecek proje dizini: {pp}\nLütfen ilk adımını at."}
    ]

    for step in range(1, max_steps + 1):
        print(f"\n{'─' * 40}\n📍 ADIM {step}/{max_steps}\n{'─' * 40}")
        try:
            r = client.chat(model=OLLAMA_MODEL, messages=msgs, options={"temperature": 0.1, "num_predict": 250})
            ar = r["message"]["content"]
        except Exception as e:
            print(f"❌ LLM Bağlantı Hatası: {e}")
            break

        print(f"\n🤖 Agent:\n{ar}")
        th, act, par, done = parse_agent_response(ar)
        msgs.append({"role": "assistant", "content": ar})

        if done:
            misses = tum_islemler_tamamlandi_mi(pp, af)
            if misses:
                # Agent erken DONE dedi — düzelt
                next_tool, next_file = get_next_task()
                obs = "REJECTED: PENDING list is not empty. Do NOT say DONE yet."
                if next_tool:
                    obs += f"\nNext: {next_tool} {next_file}"
                print(f"\n⚠️ {obs}")
                msgs.append({"role": "user", "content": obs})
                consecutive_errors += 1
                continue
            else:
                print("\n" + "=" * 60 + "\n✅ AGENT TÜM GÖREVLERİ EKSİKSİZ TAMAMLADI!\n" + "=" * 60)
                break

        if not act or act not in TOOLS:
            consecutive_errors += 1
            # Geçersiz tool — sadece hangi araçlar var söyle
            obs = (f"HATA: '{act}' geçersiz. "
                   f"Kullanılabilir araçlar: {', '.join(TOOLS.keys())}, DONE")
            # 3+ arka arkaya hata → kurtarma modu, direkt söyle
            if consecutive_errors >= 5:
                next_tool, next_file = get_next_task()
                if next_tool:
                    obs += f"\nKURTARMA: {next_tool} {next_file}"
            print(f"\n⚠️ {obs}")
        else:
            clean_par = par.replace(pp + "/", "").replace(pp + "\\", "")
            if clean_par in af and act in af[clean_par]:
                consecutive_errors += 1
                obs = f"❌ '{clean_par}' üzerinde '{act}' ZATEN YAPILDI! Başka dosyaya geç."
                if consecutive_errors >= 5:
                    next_tool, next_file = get_next_task()
                    if next_tool:
                        obs += f"\nKURTARMA: {next_tool} {next_file}"
                print(f"\n👁️ Sistem Yanıtı:\n{obs}")
            else:
                print(f"\n⚡ Çalıştırılıyor: {act}('{par}')")
                obs = execute_tool(act, par, pp)
                print(f"\n👁️ Sistem Yanıtı:\n{obs[:500]}{'...' if len(obs) > 500 else ''}")

                if obs.startswith("HATA:") or obs.startswith("Hata:"):
                    consecutive_errors += 1
                    if consecutive_errors >= 5:
                        next_tool, next_file = get_next_task()
                        if next_tool:
                            obs += f"\nKURTARMA: {next_tool} {next_file}"
                else:
                    consecutive_errors = 0  # Başarılı → sayaç sıfırla
                    af.setdefault(clean_par, []).append(act)
                    if act in ["kod_analiz", "guvenlik_tara", "bagimlilik_kontrol"]:
                        bl.append(f"[{act}] {clean_par}:\n{obs}")

        # Hafıza özetini model-dostu formatta oluştur
        done_summary = []
        pending_summary = []
        for f in all_project_files:
            tools_done = af.get(f, [])
            if f.endswith('.py'):
                needed = ['kod_analiz', 'guvenlik_tara']
            elif f.endswith(CONFIG_EXT) or 'config' in f.lower():
                needed = ['guvenlik_tara']
            elif f == 'requirements.txt':
                needed = ['bagimlilik_kontrol']
            else:
                continue
            remaining = [t for t in needed if t not in tools_done]
            if remaining:
                pending_summary.append(f"{f} needs: {', '.join(remaining)}")
            else:
                done_summary.append(f"{f}: DONE")

        memory_text = "COMPLETED:\n"
        if done_summary:
            memory_text += "\n".join(f"  [x] {d}" for d in done_summary)
        else:
            memory_text += "  (none yet)"
        memory_text += "\n\nPENDING:\n"
        if pending_summary:
            memory_text += "\n".join(f"  [ ] {p}" for p in pending_summary)
        else:
            memory_text += "  (none - all done!)"

        env_state = f"Result:\n{obs}\n\n[Memory]\n{memory_text}"
        msgs.append({"role": "user", "content": env_state})

    else:
        print(f"\n⚠️ Maksimum adım sayısına ({max_steps}) ulaşıldı.")

    # Rapor oluştur (ekrana yazdır ama dosyaya KAYDETME — Streamlit'ten yapılacak)
    if bl:
        rapor = rapor_olustur(bl)
        print(rapor)

    print("AGENT'IN KAPSADIGI ALANLAR (Hafiza Ozeti):")
    for f, t in af.items():
        print(f"   {f} -> [{', '.join(t)}]")
    return bl


# =====================================================================
if __name__ == "__main__":
    # Windows'ta emoji/Türkçe karakter konsol hatası engelle
    import sys
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass

    print("""
    +----------------------------------------------------------+
    |   Otonom Kod Analiz Agenti v4.1                          |
    |   AST + Regex Tabanli Derin Analiz                       |
    |   Acimasiz Yonetici + Otomatik PDF Rapor                 |
    +----------------------------------------------------------+
    """)

    try:
        py = input("Analiz edilecek proje yolu (varsayilan: ./test_proje):\n> ").strip()
        if not py:
            py = "./test_proje"
    except (EOFError, KeyboardInterrupt):
        print("\nCikis yapiliyor...")
        sys.exit(0)

    if not os.path.exists(py):
        print(f"HATA: Klasor bulunamadi: {py}")
        input("Kapatmak icin Enter'a basin...")
        sys.exit(1)

    bl = run_agent(py)

    # Programin hemen kapanmasini engelle
    input("\nProgram bitti. Kapatmak icin Enter'a basin...")