from .crowdstrike import CrowdStrikeConnector
from .expel import ExpelConnector
from .jira import JiraConnector
from .qualys import QualysConnector
from .wiz import WizConnector

CONNECTORS = {c.id: c() for c in (QualysConnector, CrowdStrikeConnector, ExpelConnector, WizConnector, JiraConnector)}
