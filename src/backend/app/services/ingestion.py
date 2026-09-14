import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from app.models.alert import AlertSeverity, AlertSource, AlertStatus


# Common Regex patterns for automated indicator extraction
IPV4_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
MD5_REGEX = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA256_REGEX = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_REGEX = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|io|corp|internal|example|local)\b", re.IGNORECASE)


class NormalizedSecurityEvent:
    def __init__(
        self,
        event_id: str,
        source: AlertSource,
        source_label: str,
        source_type: str,
        timestamp: datetime,
        event_type: str,
        severity: AlertSeverity,
        title: str,
        description: str,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        source_port: Optional[int] = None,
        destination_port: Optional[int] = None,
        protocol: Optional[str] = None,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
        domain: Optional[str] = None,
        file_hash: Optional[str] = None,
        process_name: Optional[str] = None,
        command_line: Optional[str] = None,
        url: Optional[str] = None,
        mitre_techniques: Optional[List[str]] = None,
        indicators: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ):
        self.event_id = event_id
        self.source = source
        self.source_label = source_label
        self.source_type = source_type
        self.timestamp = timestamp
        self.event_type = event_type
        self.severity = severity
        self.title = title
        self.description = description
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol
        self.hostname = hostname
        self.username = username
        self.domain = domain
        self.file_hash = file_hash
        self.process_name = process_name
        self.command_line = command_line
        self.url = url
        self.mitre_techniques = mitre_techniques or []
        self.indicators = indicators or []
        self.metadata = metadata or {}
        self.raw_data = raw_data or {}


class AlertIngestionEngine:
    """Multi-source ingestion and normalization engine for security telemetry."""

    @classmethod
    def extract_indicators_from_text(cls, text: str) -> List[str]:
        """Automatically extracts potential IPs, domains, and hashes from text."""
        indicators = set()
        if not text:
            return []

        for ip in IPV4_REGEX.findall(text):
            if not ip.startswith("127.") and not ip.startswith("0."):
                indicators.add(ip)

        for domain in DOMAIN_REGEX.findall(text):
            indicators.add(domain)

        for h in SHA256_REGEX.findall(text):
            indicators.add(h)

        for h in MD5_REGEX.findall(text):
            indicators.add(h)

        return list(indicators)

    @classmethod
    def normalize_severity(cls, raw_sev: Any) -> AlertSeverity:
        """Maps various vendor severity scales to AlertSeverity enum."""
        if isinstance(raw_sev, (int, float)):
            if raw_sev >= 80 or raw_sev == 1:  # scale 1-5 or 0-100
                return AlertSeverity.CRITICAL
            elif raw_sev >= 60 or raw_sev == 2:
                return AlertSeverity.HIGH
            elif raw_sev >= 40 or raw_sev == 3:
                return AlertSeverity.MEDIUM
            else:
                return AlertSeverity.LOW

        s = str(raw_sev).strip().lower()
        if s in ["critical", "crit", "severe", "fatal", "emergency", "p1"]:
            return AlertSeverity.CRITICAL
        elif s in ["high", "err", "error", "major", "p2"]:
            return AlertSeverity.HIGH
        elif s in ["medium", "med", "warn", "warning", "moderate", "p3"]:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    @classmethod
    def normalize_timestamp(cls, raw_ts: Any) -> datetime:
        """Parses vendor timestamps into UTC datetime."""
        if isinstance(raw_ts, datetime):
            return raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)

        if isinstance(raw_ts, (int, float)):
            try:
                # Check if milliseconds or seconds
                secs = raw_ts / 1000.0 if raw_ts > 1e11 else raw_ts
                return datetime.fromtimestamp(secs, tz=timezone.utc)
            except Exception:
                pass

        if isinstance(raw_ts, str):
            for fmt in [
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%d %H:%M:%S",
            ]:
                try:
                    dt = datetime.strptime(raw_ts.replace("Z", "+0000"), fmt)
                    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue

        return datetime.now(timezone.utc)

    @classmethod
    def normalize_event(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        """Dispatches to source-specific normalizer or smart generic parser."""
        source_hint = str(
            raw.get("source")
            or raw.get("source_type")
            or raw.get("vendor")
            or raw.get("log_source")
            or ""
        ).lower()

        # 1. EDR Telemetry (CrowdStrike / Defender / Carbon Black)
        if any(k in source_hint for k in ["edr", "endpoint", "crowdstrike", "defender", "carbonblack"]) or any(k in raw for k in ["process_name", "cmdline", "parent_process", "sha256", "agent_id"]):
            return cls._parse_edr(raw)

        # 2. SIEM Log (QRadar / Splunk / Elastic / LogRhythm)
        elif any(k in source_hint for k in ["siem", "qradar", "splunk", "elastic", "arcsight"]) or any(k in raw for k in ["rule_name", "offense_id", "sourcetype", "event_count"]):
            return cls._parse_siem(raw)

        # 3. Firewall Event (Palo Alto / Fortinet / Checkpoint / pfSense)
        elif any(k in source_hint for k in ["firewall", "paloalto", "fortinet", "checkpoint", "fw"]) or any(k in raw for k in ["sport", "dport", "src_zone", "dst_zone", "nat_port"]):
            return cls._parse_firewall(raw)

        # 4. Network Sensor / NIDS (Zeek / Suricata / Snort)
        elif any(k in source_hint for k in ["network", "sensor", "zeek", "suricata", "snort", "bro"]) or any(k in raw for k in ["id.orig_h", "id.resp_h", "flow_id"]):
            return cls._parse_network_sensor(raw)

        # 5. Threat Intelligence Feed (MISP / AlienVault OTX / VirusTotal)
        elif any(k in source_hint for k in ["threat-feed", "intel", "feed", "misp", "otx", "threat_feed"]) or any(k in raw for k in ["indicator_value", "pulse_id", "threat_actor"]):
            return cls._parse_threat_intel(raw)

        # 6. Cyber Sensors / Intelligence Reports / Generic
        else:
            return cls._parse_generic(raw)

    @classmethod
    def _parse_edr(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        event_id = str(raw.get("event_id") or raw.get("id") or raw.get("alert_id") or "")
        title = raw.get("title") or raw.get("name") or raw.get("event_name") or "Suspicious endpoint activity detected"
        desc = raw.get("description") or raw.get("summary") or f"EDR telemetry flagged execution of {raw.get('process_name', 'binary')}"
        sev = cls.normalize_severity(raw.get("severity") or raw.get("level") or "high")
        ts = cls.normalize_timestamp(raw.get("timestamp") or raw.get("created_at") or raw.get("time"))

        hostname = raw.get("hostname") or raw.get("computer_name") or raw.get("device_name") or raw.get("host")
        username = raw.get("username") or raw.get("user") or raw.get("account_name")
        file_hash = raw.get("file_hash") or raw.get("sha256") or raw.get("md5")
        process_name = raw.get("process_name") or raw.get("process") or raw.get("image")
        command_line = raw.get("command_line") or raw.get("cmdline") or raw.get("command")

        indicators = list(raw.get("indicators", []))
        if file_hash and file_hash not in indicators:
            indicators.append(file_hash)
        if hostname and hostname not in indicators:
            indicators.append(hostname)
        if process_name and process_name not in indicators:
            indicators.append(process_name)

        # Automatically extract additional indicators from description & command line
        indicators.extend(cls.extract_indicators_from_text(f"{desc} {command_line or ''}"))

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=AlertSource.EDR,
            source_label="EDR Endpoint Agent",
            source_type="EDR",
            timestamp=ts,
            event_type=raw.get("event_type") or "process_execution",
            severity=sev,
            title=title,
            description=desc,
            hostname=hostname,
            username=username,
            file_hash=file_hash,
            process_name=process_name,
            command_line=command_line,
            mitre_techniques=raw.get("mitre_techniques") or raw.get("techniques") or [],
            indicators=list(set(indicators)),
            metadata={k: v for k, v in raw.items() if k not in ["raw_data"]},
            raw_data=raw,
        )

    @classmethod
    def _parse_siem(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        event_id = str(raw.get("event_id") or raw.get("offense_id") or raw.get("id") or "")
        title = raw.get("title") or raw.get("rule_name") or raw.get("offense_name") or "Correlated SIEM security rule match"
        desc = raw.get("description") or raw.get("message") or f"SIEM aggregation triggered by rule {raw.get('rule_name', '')}"
        sev = cls.normalize_severity(raw.get("severity") or raw.get("magnitude") or "medium")
        ts = cls.normalize_timestamp(raw.get("timestamp") or raw.get("start_time") or raw.get("deviceTime"))

        src_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("sourceIPAddress")
        dst_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("destinationIPAddress")
        username = raw.get("username") or raw.get("user") or raw.get("sourceUserName")
        hostname = raw.get("hostname") or raw.get("host") or raw.get("deviceHostName")

        indicators = list(raw.get("indicators", []))
        if src_ip and src_ip not in indicators:
            indicators.append(src_ip)
        if dst_ip and dst_ip not in indicators:
            indicators.append(dst_ip)
        indicators.extend(cls.extract_indicators_from_text(f"{title} {desc}"))

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=AlertSource.SIEM,
            source_label="SIEM",
            source_type="SIEM",
            timestamp=ts,
            event_type=raw.get("event_type") or "security_rule_match",
            severity=sev,
            title=title,
            description=desc,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=raw.get("source_port") or raw.get("src_port"),
            destination_port=raw.get("destination_port") or raw.get("dst_port"),
            protocol=raw.get("protocol") or raw.get("proto"),
            hostname=hostname,
            username=username,
            mitre_techniques=raw.get("mitre_techniques") or raw.get("techniques") or [],
            indicators=list(set(indicators)),
            metadata={k: v for k, v in raw.items() if k not in ["raw_data"]},
            raw_data=raw,
        )

    @classmethod
    def _parse_firewall(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        event_id = str(raw.get("event_id") or raw.get("id") or raw.get("session_id") or "")
        action = raw.get("action") or raw.get("verdict") or "denied"
        src_ip = raw.get("source_ip") or raw.get("src") or raw.get("src_ip")
        dst_ip = raw.get("destination_ip") or raw.get("dst") or raw.get("dst_ip")
        dst_port = raw.get("destination_port") or raw.get("dport") or raw.get("port")
        proto = raw.get("protocol") or raw.get("proto") or "TCP"

        title = raw.get("title") or f"Perimeter firewall {action} traffic {src_ip or 'src'} -> {dst_ip or 'dst'}:{dst_port or ''}"
        desc = raw.get("description") or f"Firewall policy {raw.get('policy_name', 'rule')} {action} connection from {src_ip}:{raw.get('sport', '*')} to {dst_ip}:{dst_port} via {proto}"
        sev = cls.normalize_severity(raw.get("severity") or "low")
        ts = cls.normalize_timestamp(raw.get("timestamp") or raw.get("time"))

        indicators = list(raw.get("indicators", []))
        if src_ip:
            indicators.append(src_ip)
        if dst_ip:
            indicators.append(dst_ip)

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=AlertSource.NETWORK_SENSOR,
            source_label="Firewall Sensor",
            source_type="Firewall",
            timestamp=ts,
            event_type=raw.get("event_type") or "network_policy_violation",
            severity=sev,
            title=title,
            description=desc,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=raw.get("source_port") or raw.get("sport"),
            destination_port=dst_port,
            protocol=proto,
            mitre_techniques=raw.get("mitre_techniques") or [],
            indicators=list(set(indicators)),
            metadata={k: v for k, v in raw.items() if k not in ["raw_data"]},
            raw_data=raw,
        )

    @classmethod
    def _parse_network_sensor(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        event_id = str(raw.get("event_id") or raw.get("id") or raw.get("uid") or "")
        src_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("id.orig_h") or raw.get("src")
        dst_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("id.resp_h") or raw.get("dst")
        src_port = raw.get("source_port") or raw.get("id.orig_p")
        dst_port = raw.get("destination_port") or raw.get("id.resp_p")
        proto = raw.get("protocol") or raw.get("proto") or "TCP"
        signature = raw.get("signature") or raw.get("alert", {}).get("signature") or "Anomalous network flow"

        title = raw.get("title") or f"NIDS Alert: {signature}"
        desc = raw.get("description") or f"Network detection signature '{signature}' observed between {src_ip} and {dst_ip}"
        sev = cls.normalize_severity(raw.get("severity") or raw.get("alert", {}).get("severity") or "high")
        ts = cls.normalize_timestamp(raw.get("timestamp") or raw.get("time"))

        indicators = list(raw.get("indicators", []))
        if src_ip:
            indicators.append(src_ip)
        if dst_ip:
            indicators.append(dst_ip)
        indicators.extend(cls.extract_indicators_from_text(f"{title} {desc}"))

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=AlertSource.NETWORK_SENSOR,
            source_label="Network Sensor",
            source_type="Network Sensor",
            timestamp=ts,
            event_type=raw.get("event_type") or "network_signature_match",
            severity=sev,
            title=title,
            description=desc,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            protocol=proto,
            mitre_techniques=raw.get("mitre_techniques") or [],
            indicators=list(set(indicators)),
            metadata={k: v for k, v in raw.items() if k not in ["raw_data"]},
            raw_data=raw,
        )

    @classmethod
    def _parse_threat_intel(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        event_id = str(raw.get("event_id") or raw.get("id") or raw.get("pulse_id") or "")
        ioc = raw.get("indicator_value") or raw.get("indicator") or raw.get("ioc") or "unknown_ioc"
        actor = raw.get("threat_actor") or raw.get("campaign") or "Adversary infrastructure"
        title = raw.get("title") or f"Threat intelligence feed match: {ioc}"
        desc = raw.get("description") or f"Indicator {ioc} identified as active infrastructure associated with {actor}"
        sev = cls.normalize_severity(raw.get("severity") or raw.get("confidence") or "high")
        ts = cls.normalize_timestamp(raw.get("timestamp") or raw.get("created"))

        indicators = list(raw.get("indicators", []))
        if ioc and ioc not in indicators:
            indicators.append(ioc)

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=AlertSource.THREAT_FEED,
            source_label="Threat Intel Feed",
            source_type="Threat Intelligence",
            timestamp=ts,
            event_type=raw.get("event_type") or "intel_ioc_match",
            severity=sev,
            title=title,
            description=desc,
            mitre_techniques=raw.get("mitre_techniques") or [],
            indicators=list(set(indicators)),
            metadata={k: v for k, v in raw.items() if k not in ["raw_data"]},
            raw_data=raw,
        )

    @classmethod
    def _parse_generic(cls, raw: Dict[str, Any]) -> NormalizedSecurityEvent:
        event_id = str(raw.get("event_id") or raw.get("id") or "")
        title = raw.get("title") or raw.get("name") or "Security alert detected"
        desc = raw.get("description") or raw.get("details") or raw.get("message") or "Security telemetry event"
        sev = cls.normalize_severity(raw.get("severity") or "medium")
        ts = cls.normalize_timestamp(raw.get("timestamp") or raw.get("time"))

        # Determine source
        source_str = str(raw.get("source") or "").lower()
        if "siem" in source_str:
            src_enum = AlertSource.SIEM
            lbl = "SIEM"
        elif "edr" in source_str or "endpoint" in source_str:
            src_enum = AlertSource.EDR
            lbl = "EDR Endpoint Agent"
        elif "feed" in source_str or "intel" in source_str:
            src_enum = AlertSource.THREAT_FEED
            lbl = "Threat Intel Feed"
        else:
            src_enum = AlertSource.NETWORK_SENSOR
            lbl = raw.get("source_label") or "Cyber Sensor"

        indicators = list(raw.get("indicators", []))
        indicators.extend(cls.extract_indicators_from_text(f"{title} {desc}"))

        return NormalizedSecurityEvent(
            event_id=event_id,
            source=src_enum,
            source_label=lbl,
            source_type=raw.get("source_type") or "Sensor",
            timestamp=ts,
            event_type=raw.get("event_type") or "generic_telemetry",
            severity=sev,
            title=title,
            description=desc,
            source_ip=raw.get("source_ip") or raw.get("src_ip"),
            destination_ip=raw.get("destination_ip") or raw.get("dst_ip"),
            source_port=raw.get("source_port"),
            destination_port=raw.get("destination_port"),
            protocol=raw.get("protocol"),
            hostname=raw.get("hostname") or raw.get("host"),
            username=raw.get("username") or raw.get("user"),
            domain=raw.get("domain"),
            file_hash=raw.get("file_hash") or raw.get("hash"),
            process_name=raw.get("process_name") or raw.get("process"),
            command_line=raw.get("command_line"),
            url=raw.get("url"),
            mitre_techniques=raw.get("mitre_techniques") or [],
            indicators=list(set(indicators)),
            metadata={k: v for k, v in raw.items() if k not in ["raw_data"]},
            raw_data=raw,
        )
