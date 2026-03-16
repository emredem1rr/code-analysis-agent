# 🤖 Otonom Kod Analiz Agenti 

Lokal LLM (Ollama + llama3.2) ile çalışan, tamamen otonom AI destekli kod güvenlik ve kalite analiz aracı.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![Ollama](https://img.shields.io/badge/Ollama-Local%20LLM-brightgreen)](https://ollama.ai)
[![Streamlit](https://img.shields.io/badge/Streamlit-Web%20UI-red)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

## 📋 Proje Hakkında

Bu proje, bir AI agent'ın lokal LLM kullanarak Python projelerini **tamamen otonom** şekilde analiz etmesini sağlar. Agent, ReAct (Reasoning + Acting) mimarisi ile kendi kararlarını verir — sabit bir iş akışı yoktur, her adımda düşünür ve karar verir.

### Nasıl Çalışır?

```
LLM Düşünür (Thought) → Karar Verir (Action) → Tool Çalışır → Sonucu Görür → Tekrar Düşünür...
```

Agent hangi dosyayı, hangi sırada, hangi araçla analiz edeceğine **kendisi** karar verir.

## ✨ Özellikler

- **Otonom AI Agent** — ReAct döngüsü ile insan müdahalesi olmadan çalışır
- **Lokal LLM** — Ollama + llama3.2:3b, internet gerektirmez
- **AST Tabanlı Derin Analiz** — Python Abstract Syntax Tree ile kod yapısını anlar
- **30+ Güvenlik Kuralı** — eval, exec, SQL injection, hardcoded secret, path traversal...
- **Regex Secret Scanner** — 7 farklı pattern ile gizli bilgi tespiti
- **Bağımlılık Kontrolü** — CVE veritabanına göre eski/zafiyetli paket tespiti
- **Profesyonel PDF Rapor** — reportlab ile renkli, seviyeli PDF çıktısı
- **Streamlit Web Arayüzü** — Dark theme, dosya filtresi, kategorili bulgu kartları

## 🔍 Tespit Edilen Güvenlik Kuralları

| Kategori | Kurallar |
|----------|---------|
| **Kritik Güvenlik** | eval(), exec(), pickle.load(), os.system(), subprocess shell=True |
| **SQL Injection** | f-string, format(), % operator, string concatenation |
| **Secret Tespiti** | API key, password, token, AWS secret, JWT, Stripe, connection string |
| **Zayıf Kripto** | MD5, SHA1 hash kullanımı |
| **Config Tarama** | .json, .yaml, .env dosyalarında düz metin secret |
| **Kod Kalitesi** | Uzun fonksiyon, yüksek complexity, duplicate fonksiyon, dead code |
| **Bağımlılık** | Flask CVE, PyYAML CVE, eski versiyon, sabitlenmemiş paket |

## 🚀 Kurulum

### Gereksinimler
- Python 3.8+
- Ollama (lokal LLM çalıştırıcı)

### Adımlar

```bash
# 1. Ollama kur (https://ollama.ai)
# 2. Model indir
ollama pull llama3.2:3b

# 3. Python bağımlılıkları
pip install ollama streamlit reportlab

# 4. Repoyu klonla
git clone https://github.com/emredem1rr/code-analysis-agent.git
cd code-analysis-agent
```

## 💻 Kullanım

### Terminal (Agent)
```bash
python agent.py
```
Agent çalışır, proje yolunu sorar, otonom analiz başlar.

### Web Arayüzü (Streamlit)
```bash
streamlit run ui.py
```
Tarayıcıda açılır, "Analizi Başlat" butonuna tıkla.

## 📁 Proje Yapısı

```
code-analysis-agent/
├── agent.py              # Ana agent kodu (1350+ satır)
│   ├── Tool'lar          # klasor_listele, kod_analiz, guvenlik_tara...
│   ├── AST Analiz        # Python syntax tree tabanlı derin analiz
│   ├── Regex Scanner     # 7 pattern ile secret tespiti
│   ├── ReAct Loop        # LLM karar döngüsü
│   └── PDF Rapor         # reportlab ile profesyonel çıktı
├── ui.py                 # Streamlit web arayüzü
├── requirements.txt      # Python bağımlılıkları
├── claude-test/          # Test dosyaları (Claude modeli)
├── deepseek-test/        # Test dosyaları (DeepSeek modeli)
├── gemini-test/          # Test dosyaları (Gemini modeli)
└── gpt-test/             # Test dosyaları (GPT modeli)
```

## 🏗️ Mimari

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Ollama     │◄───►│  AI Agent    │◄───►│   Tool'lar  │
│ llama3.2:3b  │     │ (ReAct Loop) │     │             │
│  Lokal LLM   │     │              │     │ kod_analiz  │
└─────────────┘     │  Thought ──►  │     │ guvenlik    │
                    │  Action  ──►  │     │ bagimlilik  │
                    │  Observe ──►  │     │ klasor      │
                    └──────────────┘     └─────────────┘
                           │
                    ┌──────▼──────┐
                    │   Rapor     │
                    │ PDF / Text  │
                    │ Streamlit   │
                    └─────────────┘
```

## 📊 Örnek Çıktı

Test projesi üzerinde çalıştırıldığında:

| Seviye | Bulgu Sayısı | Örnekler |
|--------|-------------|----------|
| 🔴 Yüksek | 13 | SQL Injection, eval(), pickle, path traversal |
| 🟡 Orta | 40 | Hardcoded password, MD5 hash, DEBUG=True |
| 🔵 Düşük | 38 | Missing docstring, unused import, dead code |
| **Toplam** | **91** | 7 dosya, 15 adımda tamamlandı |

## 🧪 Test Edilen LLM Modelleri

Proje farklı lokal LLM modelleriyle test edilmiştir:
- **llama3.2:3b** — Ana model, 15 adımda tamamlıyor
- **DeepSeek** — Alternatif test
- **Gemini** — Alternatif test
- **GPT** — Alternatif test

## 🛠️ Kullanılan Teknolojiler

| Teknoloji | Kullanım |
|-----------|---------|
| **Python** | Ana programlama dili |
| **Ollama** | Lokal LLM çalıştırma |
| **llama3.2:3b** | Yapay zeka modeli |
| **AST (Abstract Syntax Tree)** | Python kod yapısı analizi |
| **Regex** | Pattern tabanlı güvenlik taraması |
| **Streamlit** | Web arayüzü |
| **reportlab** | PDF rapor oluşturma |

## 📄 Lisans

MIT License

## 👤 Geliştirici

**Emre Demir** — [GitHub](https://github.com/emredem1rr) · [LinkedIn](https://www.linkedin.com/in/emre-demir-7a1757257/)
