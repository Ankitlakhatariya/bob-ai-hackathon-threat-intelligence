from enum import Enum
from typing import Set, Dict


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    COMMANDER = "COMMANDER"
    VIEWER = "VIEWER"


class Permission(str, Enum):
    # Admin capabilities
    USERS_MANAGE = "users:manage"
    DATA_SOURCES_MANAGE = "data_sources:manage"
    SYSTEM_CONFIG = "system:config"

    # Alerts capabilities
    ALERTS_READ = "alerts:read"
    ALERTS_WRITE = "alerts:write"

    # Threats / Incidents capabilities
    THREATS_READ = "threats:read"
    THREATS_WRITE = "threats:write"
    CORRELATION_RUN = "correlation:run"

    # Investigations capabilities
    INVESTIGATIONS_READ = "investigations:read"
    INVESTIGATIONS_WRITE = "investigations:write"

    # BLUF capabilities
    BLUF_READ = "bluf:read"
    BLUF_GENERATE = "bluf:generate"

    # Threat Intelligence capabilities
    INTELLIGENCE_READ = "intelligence:read"
    INTELLIGENCE_WRITE = "intelligence:write"

    # MITRE ATT&CK & Dashboard capabilities
    MITRE_READ = "mitre:read"
    DASHBOARD_READ = "dashboard:read"


ROLE_PERMISSIONS: Dict[UserRole, Set[Permission]] = {
    UserRole.ADMIN: {
        # Admin has all permissions
        Permission.USERS_MANAGE,
        Permission.DATA_SOURCES_MANAGE,
        Permission.SYSTEM_CONFIG,
        Permission.ALERTS_READ,
        Permission.ALERTS_WRITE,
        Permission.THREATS_READ,
        Permission.THREATS_WRITE,
        Permission.CORRELATION_RUN,
        Permission.INVESTIGATIONS_READ,
        Permission.INVESTIGATIONS_WRITE,
        Permission.BLUF_READ,
        Permission.BLUF_GENERATE,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_WRITE,
        Permission.MITRE_READ,
        Permission.DASHBOARD_READ,
    },
    UserRole.ANALYST: {
        # Analyst manages alerts, investigations, correlations, BLUF, and intel
        Permission.ALERTS_READ,
        Permission.ALERTS_WRITE,
        Permission.THREATS_READ,
        Permission.THREATS_WRITE,
        Permission.CORRELATION_RUN,
        Permission.INVESTIGATIONS_READ,
        Permission.INVESTIGATIONS_WRITE,
        Permission.BLUF_READ,
        Permission.BLUF_GENERATE,
        Permission.INTELLIGENCE_READ,
        Permission.INTELLIGENCE_WRITE,
        Permission.MITRE_READ,
        Permission.DASHBOARD_READ,
    },
    UserRole.COMMANDER: {
        # Commander views prioritized threats, BLUF, dashboard, and strategic intel
        # CANNOT modify raw alerts or create investigations
        Permission.ALERTS_READ,
        Permission.THREATS_READ,
        Permission.BLUF_READ,
        Permission.INTELLIGENCE_READ,
        Permission.MITRE_READ,
        Permission.DASHBOARD_READ,
    },
    UserRole.VIEWER: {
        # Read-only access to monitoring views
        Permission.ALERTS_READ,
        Permission.THREATS_READ,
        Permission.BLUF_READ,
        Permission.MITRE_READ,
        Permission.DASHBOARD_READ,
    },
}


def get_permissions_for_role(role: UserRole) -> Set[Permission]:
    return ROLE_PERMISSIONS.get(role, set())
