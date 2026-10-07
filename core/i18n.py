"""
SyncHunt - internationalisation (i18n)

SyncHunt translates its own human-facing scaffolding: CLI status lines, report
headings and notification text. Tool names, config keys, artefact names and the
JSON/CSV field names stay in English on purpose - they are identifiers that
scripts, CI jobs and API consumers depend on.

    synchunt -d example.com --lang es
    general:
      language: "hi"
    export SYNCHUNT_LANG=fr

Adding a language is a data change, not a code change: add a dictionary to
TRANSLATIONS with the same keys. Missing keys fall back to English, and a key
missing everywhere falls back to the key itself, so nothing ever crashes.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional

DEFAULT_LANGUAGE = "en"

LANGUAGE_NAMES: Dict[str, str] = {
    "en": "English",
    "es": "Español",
    "fr": "Français",
    "de": "Deutsch",
    "pt": "Português",
    "hi": "हिन्दी",
    "ja": "日本語",
    "zh": "中文",
}

# Aliases seen in the wild -> catalogue code.
ALIASES = {
    "en-us": "en", "en-gb": "en", "english": "en",
    "es-es": "es", "es-mx": "es", "spanish": "es", "español": "es",
    "fr-fr": "fr", "french": "fr", "français": "fr",
    "de-de": "de", "german": "de", "deutsch": "de",
    "pt-br": "pt", "pt-pt": "pt", "portuguese": "pt", "português": "pt",
    "hi-in": "hi", "hindi": "hi",
    "ja-jp": "ja", "japanese": "ja",
    "zh-cn": "zh", "zh-tw": "zh", "chinese": "zh",
}

TRANSLATIONS: Dict[str, Dict[str, str]] = {
    "en": {
        "cli.profile": "Using profile '{profile}' ({count} phases)",
        "cli.targets": "Targets: {targets}",
        "cli.output": "Output directory: {path}",
        "cli.proxy": "Proxy: {proxy}",
        "cli.auth": "Authentication: {state}",
        "cli.dry_run": "DRY RUN - no traffic will be sent",
        "cli.complete": "Scan complete: {findings} finding(s) in {duration}",
        "cli.language": "Language: {language}",
        "summary.title": "Scan summary",
        "summary.target": "Target",
        "summary.started": "Started",
        "summary.finished": "Finished",
        "summary.findings": "Findings",
        "summary.severity": "Severity",
        "summary.critical": "Critical",
        "summary.high": "High",
        "summary.categories": "Categories",
        "summary.none": "No findings were recorded.",
        "summary.artifacts": "Artifacts",
        "report.title": "Security assessment report",
        "report.findings": "Findings",
        "report.priority": "Priority",
        "report.evidence": "Evidence",
        "report.remediation": "Remediation",
        "report.history": "Compared to the previous scan",
        "report.new": "New",
        "report.fixed": "Fixed",
        "report.persisting": "Persisting",
        "notify.summary": "{target}: {findings} finding(s), {critical} critical",
        "notify.critical": "CRITICAL FINDING on {target}: {title}",
    },
    "es": {
        "cli.profile": "Usando perfil '{profile}' ({count} fases)",
        "cli.targets": "Objetivos: {targets}",
        "cli.output": "Directorio de salida: {path}",
        "cli.proxy": "Proxy: {proxy}",
        "cli.auth": "Autenticación: {state}",
        "cli.dry_run": "SIMULACIÓN - no se enviará tráfico",
        "cli.complete": "Escaneo completado: {findings} hallazgo(s) en {duration}",
        "cli.language": "Idioma: {language}",
        "summary.title": "Resumen del escaneo",
        "summary.target": "Objetivo",
        "summary.started": "Inicio",
        "summary.finished": "Fin",
        "summary.findings": "Hallazgos",
        "summary.severity": "Severidad",
        "summary.critical": "Crítico",
        "summary.high": "Alto",
        "summary.categories": "Categorías",
        "summary.none": "No se registraron hallazgos.",
        "summary.artifacts": "Artefactos",
        "report.title": "Informe de evaluación de seguridad",
        "report.findings": "Hallazgos",
        "report.priority": "Prioridad",
        "report.evidence": "Evidencia",
        "report.remediation": "Remediación",
        "report.history": "Comparado con el escaneo anterior",
        "report.new": "Nuevos",
        "report.fixed": "Corregidos",
        "report.persisting": "Persistentes",
        "notify.summary": "{target}: {findings} hallazgo(s), {critical} crítico(s)",
        "notify.critical": "Hallazgo crítico en {target}: {title}",
    },
    "fr": {
        "cli.profile": "Profil « {profile} » ({count} phases)",
        "cli.targets": "Cibles : {targets}",
        "cli.output": "Répertoire de sortie : {path}",
        "cli.proxy": "Proxy : {proxy}",
        "cli.auth": "Authentification : {state}",
        "cli.dry_run": "SIMULATION - aucun trafic ne sera envoyé",
        "cli.complete": "Analyse terminée : {findings} résultat(s) en {duration}",
        "cli.language": "Langue : {language}",
        "summary.title": "Résumé de l'analyse",
        "summary.target": "Cible",
        "summary.started": "Début",
        "summary.finished": "Fin",
        "summary.findings": "Résultats",
        "summary.severity": "Sévérité",
        "summary.critical": "Critique",
        "summary.high": "Élevé",
        "summary.categories": "Catégories",
        "summary.none": "Aucun résultat enregistré.",
        "summary.artifacts": "Artefacts",
        "report.title": "Rapport d'évaluation de sécurité",
        "report.findings": "Résultats",
        "report.priority": "Priorité",
        "report.evidence": "Preuves",
        "report.remediation": "Remédiation",
        "report.history": "Comparé à l'analyse précédente",
        "report.new": "Nouveaux",
        "report.fixed": "Corrigés",
        "report.persisting": "Persistants",
        "notify.summary": "{target} : {findings} résultat(s), {critical} critique(s)",
        "notify.critical": "Résultat critique sur {target} : {title}",
    },
    "de": {
        "cli.profile": "Profil '{profile}' ({count} Phasen)",
        "cli.targets": "Ziele: {targets}",
        "cli.output": "Ausgabeverzeichnis: {path}",
        "cli.proxy": "Proxy: {proxy}",
        "cli.auth": "Authentifizierung: {state}",
        "cli.dry_run": "TESTLAUF - es wird kein Datenverkehr gesendet",
        "cli.complete": "Scan abgeschlossen: {findings} Fund(e) in {duration}",
        "cli.language": "Sprache: {language}",
        "summary.title": "Scan-Zusammenfassung",
        "summary.target": "Ziel",
        "summary.started": "Gestartet",
        "summary.finished": "Beendet",
        "summary.findings": "Funde",
        "summary.severity": "Schweregrad",
        "summary.critical": "Kritisch",
        "summary.high": "Hoch",
        "summary.categories": "Kategorien",
        "summary.none": "Es wurden keine Funde erfasst.",
        "summary.artifacts": "Artefakte",
        "report.title": "Sicherheitsbericht",
        "report.findings": "Funde",
        "report.priority": "Priorität",
        "report.evidence": "Nachweis",
        "report.remediation": "Behebung",
        "report.history": "Vergleich zum vorherigen Scan",
        "report.new": "Neu",
        "report.fixed": "Behoben",
        "report.persisting": "Weiterhin vorhanden",
        "notify.summary": "{target}: {findings} Fund(e), {critical} kritisch",
        "notify.critical": "Kritischer Fund auf {target}: {title}",
    },
    "pt": {
        "cli.profile": "Usando perfil '{profile}' ({count} fases)",
        "cli.targets": "Alvos: {targets}",
        "cli.output": "Diretório de saída: {path}",
        "cli.proxy": "Proxy: {proxy}",
        "cli.auth": "Autenticação: {state}",
        "cli.dry_run": "SIMULAÇÃO - nenhum tráfego será enviado",
        "cli.complete": "Varredura concluída: {findings} achado(s) em {duration}",
        "cli.language": "Idioma: {language}",
        "summary.title": "Resumo da varredura",
        "summary.target": "Alvo",
        "summary.started": "Início",
        "summary.finished": "Fim",
        "summary.findings": "Achados",
        "summary.severity": "Severidade",
        "summary.critical": "Crítico",
        "summary.high": "Alto",
        "summary.categories": "Categorias",
        "summary.none": "Nenhum achado foi registrado.",
        "summary.artifacts": "Artefatos",
        "report.title": "Relatório de avaliação de segurança",
        "report.findings": "Achados",
        "report.priority": "Prioridade",
        "report.evidence": "Evidência",
        "report.remediation": "Remediação",
        "report.history": "Comparado à varredura anterior",
        "report.new": "Novos",
        "report.fixed": "Corrigidos",
        "report.persisting": "Persistentes",
        "notify.summary": "{target}: {findings} achado(s), {critical} crítico(s)",
        "notify.critical": "Achado crítico em {target}: {title}",
    },
    "hi": {
        "cli.profile": "प्रोफ़ाइल '{profile}' उपयोग में ({count} चरण)",
        "cli.targets": "लक्ष्य: {targets}",
        "cli.output": "आउटपुट निर्देशिका: {path}",
        "cli.proxy": "प्रॉक्सी: {proxy}",
        "cli.auth": "प्रमाणीकरण: {state}",
        "cli.dry_run": "ड्राई रन - कोई ट्रैफ़िक नहीं भेजा जाएगा",
        "cli.complete": "स्कैन पूर्ण: {findings} निष्कर्ष, {duration} में",
        "cli.language": "भाषा: {language}",
        "summary.title": "स्कैन सारांश",
        "summary.target": "लक्ष्य",
        "summary.started": "प्रारंभ",
        "summary.finished": "समाप्त",
        "summary.findings": "निष्कर्ष",
        "summary.severity": "गंभीरता",
        "summary.critical": "गंभीर",
        "summary.high": "उच्च",
        "summary.categories": "श्रेणियाँ",
        "summary.none": "कोई निष्कर्ष दर्ज नहीं हुआ।",
        "summary.artifacts": "आर्टिफ़ैक्ट",
        "report.title": "सुरक्षा मूल्यांकन रिपोर्ट",
        "report.findings": "निष्कर्ष",
        "report.priority": "प्राथमिकता",
        "report.evidence": "प्रमाण",
        "report.remediation": "उपचार",
        "report.history": "पिछले स्कैन की तुलना में",
        "report.new": "नए",
        "report.fixed": "ठीक हुए",
        "report.persisting": "बने हुए",
        "notify.summary": "{target}: {findings} निष्कर्ष, {critical} गंभीर",
        "notify.critical": "{target} पर गंभीर निष्कर्ष: {title}",
    },
    "ja": {
        "cli.profile": "プロファイル '{profile}' を使用（{count} フェーズ）",
        "cli.targets": "ターゲット: {targets}",
        "cli.output": "出力ディレクトリ: {path}",
        "cli.proxy": "プロキシ: {proxy}",
        "cli.auth": "認証: {state}",
        "cli.dry_run": "ドライラン - トラフィックは送信されません",
        "cli.complete": "スキャン完了: {findings} 件（{duration}）",
        "cli.language": "言語: {language}",
        "summary.title": "スキャン概要",
        "summary.target": "ターゲット",
        "summary.started": "開始",
        "summary.finished": "終了",
        "summary.findings": "検出結果",
        "summary.severity": "重大度",
        "summary.critical": "クリティカル",
        "summary.high": "高",
        "summary.categories": "カテゴリ",
        "summary.none": "検出結果はありません。",
        "summary.artifacts": "成果物",
        "report.title": "セキュリティ評価レポート",
        "report.findings": "検出結果",
        "report.priority": "優先度",
        "report.evidence": "エビデンス",
        "report.remediation": "修正案",
        "report.history": "前回スキャンとの比較",
        "report.new": "新規",
        "report.fixed": "修正済み",
        "report.persisting": "継続",
        "notify.summary": "{target}: {findings} 件、クリティカル {critical} 件",
        "notify.critical": "{target} でクリティカルな検出: {title}",
    },
    "zh": {
        "cli.profile": "使用配置文件 '{profile}'（{count} 个阶段）",
        "cli.targets": "目标：{targets}",
        "cli.output": "输出目录：{path}",
        "cli.proxy": "代理：{proxy}",
        "cli.auth": "认证：{state}",
        "cli.dry_run": "试运行 - 不会发送任何流量",
        "cli.complete": "扫描完成：{findings} 个发现（耗时 {duration}）",
        "cli.language": "语言：{language}",
        "summary.title": "扫描摘要",
        "summary.target": "目标",
        "summary.started": "开始",
        "summary.finished": "结束",
        "summary.findings": "发现",
        "summary.severity": "严重性",
        "summary.critical": "严重",
        "summary.high": "高",
        "summary.categories": "类别",
        "summary.none": "没有记录到发现。",
        "summary.artifacts": "产物",
        "report.title": "安全评估报告",
        "report.findings": "发现",
        "report.priority": "优先级",
        "report.evidence": "证据",
        "report.remediation": "修复建议",
        "report.history": "与上次扫描对比",
        "report.new": "新增",
        "report.fixed": "已修复",
        "report.persisting": "持续存在",
        "notify.summary": "{target}：{findings} 个发现，{critical} 个严重",
        "notify.critical": "{target} 上的严重发现：{title}",
    },
}

_current = DEFAULT_LANGUAGE


def available_languages() -> Dict[str, str]:
    """{code: native name} for everything with a catalogue."""
    return {code: LANGUAGE_NAMES.get(code, code) for code in sorted(TRANSLATIONS)}


def normalise(code: str) -> str:
    """'en-US' / 'English' / 'pt_br' -> 'en' / 'en' / 'pt'."""
    value = (code or "").strip().lower().replace("_", "-")
    if not value:
        return DEFAULT_LANGUAGE
    if value in TRANSLATIONS:
        return value
    if value in ALIASES:
        return ALIASES[value]
    base = value.split("-")[0]
    return base if base in TRANSLATIONS else DEFAULT_LANGUAGE


def set_language(code: str) -> str:
    """Set the active language, returning the code actually applied."""
    global _current
    _current = normalise(code)
    return _current


def get_language() -> str:
    return _current


def language_name(code: Optional[str] = None) -> str:
    resolved = normalise(code or _current)
    return LANGUAGE_NAMES.get(resolved, resolved)


def translate(key: str, lang: Optional[str] = None, **kwargs) -> str:
    """Look up `key` (English fallback, key fallback) and format it."""
    lang = normalise(lang or _current)
    template = (
        TRANSLATIONS.get(lang, {}).get(key)
        or TRANSLATIONS[DEFAULT_LANGUAGE].get(key)
        or key
    )
    if not kwargs:
        return template
    try:
        return template.format(**kwargs)
    except (KeyError, IndexError, ValueError):  # pragma: no cover - defensive
        return template


def t(key: str, **kwargs) -> str:
    """Translate using the active language."""
    return translate(key, None, **kwargs)


def configure(config=None, cli_value: str = "") -> str:
    """
    Resolve the language: CLI flag > config `general.language` > SYNCHUNT_LANG > env LANG.
    """
    chosen = (cli_value or "").strip()
    if not chosen and config is not None:
        try:
            chosen = str(config.get("general.language", "") or "").strip()
        except Exception:  # pragma: no cover - defensive
            chosen = ""
    if not chosen:
        chosen = (os.environ.get("SYNCHUNT_LANG") or "").strip()
    if not chosen:
        locale = (os.environ.get("LC_ALL") or os.environ.get("LANG") or "").strip()
        if locale and locale not in ("C", "POSIX"):
            chosen = locale
    return set_language(chosen or DEFAULT_LANGUAGE)


def describe() -> List[str]:
    """Lines for `--list-languages`."""
    lines = []
    for code, name in available_languages().items():
        marker = "*" if code == _current else " "
        lines.append(f" {marker} {code:<3} {name}")
    return lines
