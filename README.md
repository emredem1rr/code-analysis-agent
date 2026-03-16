# Otonom Kod Analiz Agenti

Lokal LLM (Ollama + llama3.2) ile çalışan AI destekli kod güvenlik ve kalite analiz aracı.

## Özellikler
- ReAct mimarisi ile otonom karar veren AI agent
- AST + Regex tabanlı derin statik analiz
- 30+ güvenlik ve kalite kuralı
- SQL Injection, eval/exec, hardcoded secret tespiti
- Profesyonel PDF rapor
- Streamlit web arayüzü

## Kurulum
```bash
pip install ollama streamlit reportlab
ollama pull llama3.2:3b
```
