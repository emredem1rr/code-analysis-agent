"""
Streamlit UI v4.2 — Otonom Kod Analiz Agenti Arayuzu
=====================================================
Kullanim: streamlit run ui.py
"""

import streamlit as st
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from agent import (
    klasor_listele, dosya_oku, kod_analiz, guvenlik_tara,
    bagimlilik_kontrol, rapor_olustur, rapor_kaydet,
    tum_islemler_tamamlandi_mi
)
import agent as agent_module

st.set_page_config(page_title="Kod Analiz Agenti v4.2", page_icon="🔒", layout="wide")

# ── DARK THEME CSS ──
st.markdown("""
<style>
    .card-high {
        background: #1a1a2e;
        border-left: 5px solid #ff4757;
        padding: 14px 18px;
        margin: 10px 0;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(255,71,87,0.15);
    }
    .card-high .card-title {
        color: #ff6b81;
        font-weight: bold;
        font-size: 15px;
        margin-bottom: 8px;
    }
    .card-medium {
        background: #1a1a2e;
        border-left: 5px solid #ffa502;
        padding: 14px 18px;
        margin: 10px 0;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(255,165,2,0.15);
    }
    .card-medium .card-title {
        color: #ffbe76;
        font-weight: bold;
        font-size: 15px;
        margin-bottom: 8px;
    }
    .card-low {
        background: #1a1a2e;
        border-left: 5px solid #3498db;
        padding: 14px 18px;
        margin: 10px 0;
        border-radius: 10px;
        box-shadow: 0 2px 8px rgba(52,152,219,0.15);
    }
    .card-low .card-title {
        color: #70a1ff;
        font-weight: bold;
        font-size: 15px;
        margin-bottom: 8px;
    }
    .card-file {
        color: #a4b0be;
        font-size: 12px;
        margin: 3px 0;
    }
    .card-code {
        background: #0d0d1a;
        color: #00d2d3;
        font-family: 'Courier New', monospace;
        font-size: 13px;
        padding: 8px 12px;
        border-radius: 6px;
        margin: 6px 0;
        border: 1px solid #2f3542;
    }
    .card-desc {
        color: #dfe6e9;
        font-size: 13px;
        margin: 4px 0;
    }
    .card-fix {
        color: #2ed573;
        font-size: 13px;
        margin: 4px 0;
    }
    [data-testid="stExpander"] {
        border: 1px solid #2f3542;
        border-radius: 10px;
        margin-bottom: 10px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🤖 Otonom Kod Analiz Agenti v4.2")
st.caption("AST + Regex Tabanli Derin Statik Analiz | Guvenlik + Kalite")

# ── Sidebar ──
with st.sidebar:
    st.header("Ayarlar")
    proje_yolu = st.text_input("Proje Klasoru", value="./claude-proje")

    if os.path.exists(proje_yolu):
        dosyalar = [d for d in os.listdir(proje_yolu)
                     if not d.startswith('rapor_') and os.path.isfile(os.path.join(proje_yolu, d))]
        st.success(f"{len(dosyalar)} dosya bulundu")
        for d in sorted(dosyalar):
            icon = "🐍" if d.endswith(".py") else "📦" if d == "requirements.txt" else "⚙️" if d.endswith(('.json','.yaml','.yml','.env')) else "📄"
            st.text(f"  {icon} {d}")
    else:
        st.error("Klasor bulunamadi")

    st.divider()
    st.markdown("**Analiz Kapsami:**")
    st.markdown(
        "Guvenlik (eval, exec, SQL injection, secret leak) · "
        "Credential (7 hardcoded secret pattern) · "
        "Kalite (complexity, long function, duplicate) · "
        "Bagimlilik (CVE, eski versiyon) · "
        "Config (.json, .yaml, .env)"
    )

# ── Analiz Baslat ──
if st.button("🚀 Analizi Baslat", type="primary", use_container_width=True):
    if not os.path.exists(proje_yolu):
        st.error("Proje klasoru bulunamadi!")
    else:
        for key in ['rapor', 'hafiza', 'proje_yolu', 'pdf_data', 'pdf_name']:
            st.session_state.pop(key, None)

        agent_module._reported_findings = set()
        bulgular = []
        hafiza = {}

        progress = st.progress(0)
        status = st.empty()

        dosyalar = [f for f in os.listdir(proje_yolu)
                     if os.path.isfile(os.path.join(proje_yolu, f)) and not f.startswith('rapor_')]
        py_files = sorted([f for f in dosyalar if f.endswith('.py')])
        config_ext = ('.json', '.yaml', '.yml', '.env', '.ini', '.cfg', '.toml')
        config_files = sorted([f for f in dosyalar if f.endswith(config_ext)
                                or ('config' in f.lower() and not f.endswith('.py'))])
        has_req = 'requirements.txt' in dosyalar

        total = len(py_files) * 2 + len(config_files) + (1 if has_req else 0)
        step = 0

        with st.expander("Adim Adim Analiz Loglari", expanded=True):
            for fn in py_files:
                fp = os.path.join(proje_yolu, fn)
                step += 1; progress.progress(step / total)
                status.info(f"kod_analiz → {fn}")
                st.markdown(f"**kod_analiz: {fn}**")
                r = kod_analiz(fp)
                bulgular.append(f"[kod_analiz] {fn}:\n{r}")
                hafiza.setdefault(fn, []).append('kod_analiz')
                st.code(r[:600], language=None)

                step += 1; progress.progress(step / total)
                status.info(f"guvenlik_tara → {fn}")
                st.markdown(f"**guvenlik_tara: {fn}**")
                r = guvenlik_tara(fp)
                bulgular.append(f"[guvenlik_tara] {fn}:\n{r}")
                hafiza.setdefault(fn, []).append('guvenlik_tara')
                st.code(r[:600], language=None)

            for fn in config_files:
                fp = os.path.join(proje_yolu, fn)
                step += 1; progress.progress(step / total)
                status.info(f"guvenlik_tara → {fn}")
                st.markdown(f"**guvenlik_tara: {fn}**")
                r = guvenlik_tara(fp)
                bulgular.append(f"[guvenlik_tara] {fn}:\n{r}")
                hafiza.setdefault(fn, []).append('guvenlik_tara')
                st.code(r[:600], language=None)

            if has_req:
                step += 1; progress.progress(step / total)
                status.info("bagimlilik_kontrol → requirements.txt")
                st.markdown("**bagimlilik_kontrol: requirements.txt**")
                r = bagimlilik_kontrol(proje_yolu)
                bulgular.append(f"[bagimlilik_kontrol] requirements.txt:\n{r}")
                hafiza.setdefault('requirements.txt', []).append('bagimlilik_kontrol')
                st.code(r[:600], language=None)

        progress.progress(1.0)
        status.success("Analiz Tamamlandi!")

        rapor = rapor_olustur(bulgular)
        st.session_state['rapor'] = rapor
        st.session_state['hafiza'] = hafiza
        st.session_state['proje_yolu'] = proje_yolu

# ══════════════════════════════════════════
# SONUCLAR
# ══════════════════════════════════════════
if 'rapor' in st.session_state:
    rapor = st.session_state['rapor']
    hafiza = st.session_state['hafiza']
    proje_yolu_sonuc = st.session_state['proje_yolu']

    # ── Bulgulari parse et ──
    all_findings = []
    for line in rapor.split("\n"):
        s = line.strip()
        if any(s.startswith(ch) for ch in ['🔴', '🟡', '🔵']):
            all_findings.append({"header": s, "details": []})
        elif any(s.startswith(p) for p in ["Dosya:", "Kod:", "Açıklama:", "Öneri:"]):
            if all_findings:
                all_findings[-1]["details"].append(s)

    high_list = [f for f in all_findings if "[HIGH]" in f["header"]]
    med_list = [f for f in all_findings if "[MEDIUM]" in f["header"]]
    low_list = [f for f in all_findings if "[LOW]" in f["header"]]

    # Dosya isimleri
    all_files = set()
    for f in all_findings:
        for d in f["details"]:
            if d.startswith("Dosya:"):
                all_files.add(d.split("|")[0].replace("Dosya:", "").strip())

    st.divider()
    st.header("📊 Analiz Sonuclari")

    # ── Metrik kartlari ──
    c1, c2, c3, c4 = st.columns(4)
    c1.markdown(f"""<div style="background:linear-gradient(135deg,#e74c3c,#c0392b);color:white;
        padding:20px;border-radius:12px;text-align:center;">
        <div style="font-size:32px;font-weight:bold;">{len(high_list)}</div>
        <div style="font-size:14px;opacity:0.9;">🔴 Yuksek</div></div>""", unsafe_allow_html=True)
    c2.markdown(f"""<div style="background:linear-gradient(135deg,#f39c12,#e67e22);color:white;
        padding:20px;border-radius:12px;text-align:center;">
        <div style="font-size:32px;font-weight:bold;">{len(med_list)}</div>
        <div style="font-size:14px;opacity:0.9;">🟡 Orta</div></div>""", unsafe_allow_html=True)
    c3.markdown(f"""<div style="background:linear-gradient(135deg,#3498db,#2980b9);color:white;
        padding:20px;border-radius:12px;text-align:center;">
        <div style="font-size:32px;font-weight:bold;">{len(low_list)}</div>
        <div style="font-size:14px;opacity:0.9;">🔵 Dusuk</div></div>""", unsafe_allow_html=True)
    c4.markdown(f"""<div style="background:linear-gradient(135deg,#2c3e50,#34495e);color:white;
        padding:20px;border-radius:12px;text-align:center;">
        <div style="font-size:32px;font-weight:bold;">{len(all_findings)}</div>
        <div style="font-size:14px;opacity:0.9;">📊 Toplam</div></div>""", unsafe_allow_html=True)

    st.write("")

    # ── Dosya filtresi ──
    col_filter, _ = st.columns([1, 2])
    with col_filter:
        secili_dosya = st.selectbox("📁 Dosyaya gore filtrele",
            ["Tum dosyalar"] + sorted(all_files), key="dosya_filtre")

    def dosya_filtre_fn(finding):
        if secili_dosya == "Tum dosyalar":
            return True
        return any(d.startswith("Dosya:") and secili_dosya in d for d in finding["details"])

    # ── Kart render fonksiyonu ──
    def render_card(f, css_class):
        baslik = f["header"]
        for ch in ['🔴', '🟡', '🔵']:
            baslik = baslik.replace(ch, "").strip()

        html = f'<div class="{css_class}"><div class="card-title">{baslik}</div>'

        for d in f["details"]:
            if d.startswith("Dosya:"):
                html += f'<div class="card-file">📍 {d}</div>'
            elif d.startswith("Kod:"):
                kod = d.replace("Kod:", "").strip()
                html += f'<div class="card-code">{kod}</div>'
            elif d.startswith("Açıklama:") or d.startswith("Aciklama:"):
                acik = d.replace("Açıklama:", "").replace("Aciklama:", "").strip()
                html += f'<div class="card-desc">💡 {acik}</div>'
            elif d.startswith("Öneri:") or d.startswith("Oneri:"):
                oneri = d.replace("Öneri:", "").replace("Oneri:", "").strip()
                html += f'<div class="card-fix">✅ {oneri}</div>'

        html += '</div>'
        st.markdown(html, unsafe_allow_html=True)

    # ── YUKSEK ──
    fh = [f for f in high_list if dosya_filtre_fn(f)]
    with st.expander(f"🔴 YUKSEK SEVİYE ({len(fh)} bulgu)", expanded=True):
        if fh:
            for f in fh:
                render_card(f, "card-high")
        else:
            st.success("Bu kategoride bulgu yok!")

    # ── ORTA ──
    fm = [f for f in med_list if dosya_filtre_fn(f)]
    with st.expander(f"🟡 ORTA SEVİYE ({len(fm)} bulgu)", expanded=False):
        if fm:
            for f in fm:
                render_card(f, "card-medium")
        else:
            st.success("Bu kategoride bulgu yok!")

    # ── DUSUK ──
    fl = [f for f in low_list if dosya_filtre_fn(f)]
    with st.expander(f"🔵 DUSUK SEVİYE ({len(fl)} bulgu)", expanded=False):
        if fl:
            for f in fl:
                render_card(f, "card-low")
        else:
            st.success("Bu kategoride bulgu yok!")

    # ── Kapsam ──
    with st.expander("📋 Kapsam Kontrolu", expanded=False):
        eksik = tum_islemler_tamamlandi_mi(proje_yolu_sonuc, hafiza)
        if not eksik:
            st.success("Tum dosyalar eksiksiz analiz edildi!")
        else:
            for e in eksik:
                st.warning(f"Eksik: {e}")
        for fn, tools in hafiza.items():
            st.text(f"  {fn} -> [{', '.join(tools)}]")

    # ── Ham Rapor ──
    with st.expander("📄 Ham Rapor (metin)", expanded=False):
        st.code(rapor, language=None)

    # ── PDF ──
    st.divider()
    if st.button("📄 PDF Rapor Olustur", type="secondary", use_container_width=True):
        with st.spinner("PDF olusturuluyor..."):
            dosya = rapor_kaydet(rapor, proje_yolu_sonuc)
        if dosya:
            with open(dosya, "rb") as f:
                st.session_state['pdf_data'] = f.read()
                st.session_state['pdf_name'] = os.path.basename(dosya)
            st.success(f"PDF olusturuldu: {dosya}")
        else:
            st.error("PDF olusturulamadi! 'pip install reportlab' calistirin.")

    if 'pdf_data' in st.session_state:
        st.download_button(
            "📥 PDF Indir",
            st.session_state['pdf_data'],
            file_name=st.session_state['pdf_name'],
            mime="application/pdf",
            use_container_width=True
        )