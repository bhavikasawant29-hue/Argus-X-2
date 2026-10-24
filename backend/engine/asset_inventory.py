"""
ARGUS-X Asset Inventory Adapter & Enterprise Asset Catalog.

Maps telemetry entities (hosts, IPs) to known asset configurations,
installed software components, vendors, and versions for version-aware CVE matching.
"""

from typing import Optional, List, Dict, Any
from models.asset import AssetRecord, InstalledSoftware


DEFAULT_ASSETS: List[Dict[str, Any]] = [
    {
        "asset_id": "ASSET-PC25",
        "hostname": "PC-25",
        "ip_address": "192.168.1.25",
        "asset_type": "workstation",
        "criticality": "medium",
        "owner": "rahul",
        "installed_software": [
            {"vendor": "Microsoft", "product": "Windows 11", "version": "22H2"},
            {"vendor": "Microsoft", "product": "PowerShell", "version": "7.1.3"},
            {"vendor": "Google", "product": "Chrome", "version": "94.0.4606.61"},
        ],
        "metadata": {"department": "Finance", "os": "Windows"},
    },
    {
        "asset_id": "ASSET-SRV02",
        "hostname": "SRV-02",
        "ip_address": "10.0.0.2",
        "asset_type": "server",
        "criticality": "high",
        "owner": "infrastructure-team",
        "installed_software": [
            {
                "vendor": "Apache",
                "product": "Log4j2",
                "version": "2.14.1",
                "cpe": "cpe:2.3:a:apache:log4j2:2.14.1:*:*:*:*:*:*:*",
            },
            {
                "vendor": "Apache",
                "product": "httpd",
                "version": "2.4.49",
                "cpe": "cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*",
            },
            {
                "vendor": "OpenSSH",
                "product": "OpenSSH",
                "version": "8.2p1",
            },
        ],
        "metadata": {"role": "Application Middleware & Internal Gateway"},
    },
    {
        "asset_id": "ASSET-DB01",
        "hostname": "DB-01",
        "ip_address": "10.0.0.10",
        "asset_type": "database",
        "criticality": "critical",
        "owner": "database-admins",
        "installed_software": [
            {"vendor": "PostgreSQL", "product": "PostgreSQL", "version": "13.3"},
            {"vendor": "OpenSSL", "product": "OpenSSL", "version": "1.1.1k"},
        ],
        "metadata": {"data_classification": "Restricted", "contains_sensitive_tables": True},
    },
    {
        "asset_id": "ASSET-SRV01",
        "hostname": "SRV-01",
        "ip_address": "10.0.0.1",
        "asset_type": "server",
        "criticality": "medium",
        "owner": "devops",
        "installed_software": [
            {"vendor": "Nginx", "product": "Nginx", "version": "1.20.1"},
            {"vendor": "OpenSSH", "product": "OpenSSH", "version": "8.4p1"},
        ],
        "metadata": {"role": "Web Proxy"},
    },
    {
        "asset_id": "ASSET-SRV03",
        "hostname": "SRV-03",
        "ip_address": "10.0.0.3",
        "asset_type": "server",
        "criticality": "medium",
        "owner": "shared-services",
        "installed_software": [
            {"vendor": "Apache", "product": "Tomcat", "version": "9.0.50"},
        ],
        "metadata": {"role": "Internal Services"},
    },
]


class AssetInventory:
    """Manages enterprise asset records and software inventory."""

    def __init__(self, raw_assets: Optional[List[Dict[str, Any]]] = None):
        self.assets: Dict[str, AssetRecord] = {}
        self.ip_to_host: Dict[str, str] = {}

        source = raw_assets if raw_assets is not None else DEFAULT_ASSETS
        for a in source:
            sw_list = [
                InstalledSoftware(**sw) if isinstance(sw, dict) else sw
                for sw in a.get("installed_software", [])
            ]
            record = AssetRecord(
                asset_id=a["asset_id"],
                hostname=a["hostname"],
                ip_address=a.get("ip_address"),
                asset_type=a.get("asset_type", "workstation"),
                criticality=a.get("criticality", "medium"),
                owner=a.get("owner"),
                installed_software=sw_list,
                metadata=a.get("metadata", {}),
            )
            self.assets[record.hostname.upper()] = record
            if record.ip_address:
                self.ip_to_host[record.ip_address] = record.hostname.upper()

    def get_by_hostname(self, hostname: Optional[str]) -> Optional[AssetRecord]:
        if not hostname:
            return None
        return self.assets.get(hostname.strip().upper())

    def get_by_ip(self, ip: Optional[str]) -> Optional[AssetRecord]:
        if not ip:
            return None
        host = self.ip_to_host.get(ip.strip())
        return self.assets.get(host) if host else None

    def find_asset(self, hostname: Optional[str] = None, ip: Optional[str] = None) -> Optional[AssetRecord]:
        if hostname and hostname.strip().upper() in self.assets:
            return self.assets[hostname.strip().upper()]
        if ip and ip.strip() in self.ip_to_host:
            return self.assets[self.ip_to_host[ip.strip()]]
        return None

    def list_all(self) -> List[AssetRecord]:
        return list(self.assets.values())

    def get_flattened_matching_items(self) -> List[Dict[str, Any]]:
        """Return flattened asset-product items suitable for match_vulnerabilities_to_assets."""
        items = []
        for asset in self.assets.values():
            for sw in asset.installed_software:
                items.append({
                    "asset_id": asset.asset_id,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "vendor": sw.vendor,
                    "product": sw.product,
                    "version": sw.version,
                    "criticality": asset.criticality,
                })
        return items


# Singleton default inventory instance
_inventory_instance: Optional[AssetInventory] = None


def get_asset_inventory() -> AssetInventory:
    global _inventory_instance
    if _inventory_instance is None:
        _inventory_instance = AssetInventory()
    return _inventory_instance
