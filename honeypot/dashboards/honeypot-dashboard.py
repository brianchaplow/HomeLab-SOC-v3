#!/usr/bin/env python3
"""
Honeypot Research Dashboard — Kibana Dashboard Builder
Creates a 15-panel dashboard via Kibana saved objects API.
"""

import json
import os
import urllib.request
import base64

KIBANA_URL = "http://10.10.30.23:5601"
KIBANA_USER = "elastic"
KIBANA_PASS = os.environ.get("ELK_PASS", "your_elastic_password")

# Data view IDs
DV_ALL = "1701a490-2a7e-455e-a81c-5c74d26410dc"       # honeypot-*
DV_CREDS = "a72440f0-c69e-4dd5-aa1c-edc057f8f046"     # honeypot-credentials
DV_ACCESS = "60449b8d-61a8-4784-b6ea-c72062c7f6cf"    # honeypot-access
DV_WAZUH = "a37e91bf-3698-4cb8-a33e-a16530de7a24"     # honeypot-wazuh

# Track all references needed at dashboard level
ALL_REFS = []


def add_ref(panel_id, dv_id, layer_id):
    """Register a dashboard-level reference for a panel's data view."""
    ALL_REFS.append({
        "type": "index-pattern",
        "id": dv_id,
        "name": f"{panel_id}:indexpattern-datasource-layer-{layer_id}"
    })


def metric_panel(panel_id, title, dv_id, agg_type="count", field=None, grid=None):
    col_id = f"{panel_id}col1"
    layer_id = f"{panel_id}layer"

    if agg_type == "count":
        col_def = {
            "label": title,
            "dataType": "number",
            "operationType": "count",
            "isBucketed": False,
            "scale": "ratio",
            "sourceField": "___records___"
        }
    else:  # unique_count
        col_def = {
            "label": title,
            "dataType": "number",
            "operationType": "unique_count",
            "isBucketed": False,
            "scale": "ratio",
            "sourceField": field
        }

    add_ref(panel_id, dv_id, layer_id)

    return {
        "version": "8.17.0",
        "type": "lens",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "type": "lens",
                "visualizationType": "lnsMetric",
                "state": {
                    "visualization": {
                        "layerId": layer_id,
                        "layerType": "data",
                        "metricAccessor": col_id
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                layer_id: {
                                    "columns": {col_id: col_def},
                                    "columnOrder": [col_id],
                                    "incompleteColumns": {},
                                    "indexPatternId": dv_id
                                }
                            }
                        }
                    },
                    "adHocDataViews": {}
                },
                "references": [
                    {"type": "index-pattern", "id": dv_id,
                     "name": f"indexpattern-datasource-layer-{layer_id}"}
                ]
            },
            "enhancements": {}
        },
        "title": title
    }


def date_histogram_panel(panel_id, title, dv_id, grid):
    layer_id = f"{panel_id}layer"
    date_col = f"{panel_id}date"
    count_col = f"{panel_id}count"

    add_ref(panel_id, dv_id, layer_id)

    return {
        "version": "8.17.0",
        "type": "lens",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "type": "lens",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "legend": {"isVisible": True, "position": "right"},
                        "valueLabels": "hide",
                        "preferredSeriesType": "bar_stacked",
                        "layers": [{
                            "layerId": layer_id,
                            "accessors": [count_col],
                            "xAccessor": date_col,
                            "seriesType": "bar_stacked",
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                layer_id: {
                                    "columns": {
                                        date_col: {
                                            "label": "@timestamp",
                                            "dataType": "date",
                                            "operationType": "date_histogram",
                                            "isBucketed": True,
                                            "scale": "interval",
                                            "sourceField": "@timestamp",
                                            "params": {"interval": "auto"}
                                        },
                                        count_col: {
                                            "label": "Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "isBucketed": False,
                                            "scale": "ratio",
                                            "sourceField": "___records___"
                                        }
                                    },
                                    "columnOrder": [date_col, count_col],
                                    "incompleteColumns": {},
                                    "indexPatternId": dv_id
                                }
                            }
                        }
                    },
                    "adHocDataViews": {}
                },
                "references": [
                    {"type": "index-pattern", "id": dv_id,
                     "name": f"indexpattern-datasource-layer-{layer_id}"}
                ]
            },
            "enhancements": {}
        },
        "title": title
    }


def pie_panel(panel_id, title, dv_id, field, grid, size=10):
    layer_id = f"{panel_id}layer"
    bucket_col = f"{panel_id}bucket"
    count_col = f"{panel_id}count"

    add_ref(panel_id, dv_id, layer_id)

    return {
        "version": "8.17.0",
        "type": "lens",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "type": "lens",
                "visualizationType": "lnsPie",
                "state": {
                    "visualization": {
                        "shape": "donut",
                        "layers": [{
                            "layerId": layer_id,
                            "primaryGroups": [bucket_col],
                            "metrics": [count_col],
                            "numberDisplay": "percent",
                            "categoryDisplay": "default",
                            "legendDisplay": "default",
                            "nestedLegend": False,
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                layer_id: {
                                    "columns": {
                                        bucket_col: {
                                            "label": "Type",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "isBucketed": True,
                                            "scale": "ordinal",
                                            "sourceField": field,
                                            "params": {
                                                "size": size,
                                                "orderBy": {"type": "column", "columnId": count_col},
                                                "orderDirection": "desc"
                                            }
                                        },
                                        count_col: {
                                            "label": "Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "isBucketed": False,
                                            "scale": "ratio",
                                            "sourceField": "___records___"
                                        }
                                    },
                                    "columnOrder": [bucket_col, count_col],
                                    "incompleteColumns": {},
                                    "indexPatternId": dv_id
                                }
                            }
                        }
                    },
                    "adHocDataViews": {}
                },
                "references": [
                    {"type": "index-pattern", "id": dv_id,
                     "name": f"indexpattern-datasource-layer-{layer_id}"}
                ]
            },
            "enhancements": {}
        },
        "title": title
    }


def hbar_panel(panel_id, title, dv_id, field, grid, size=15, label=None):
    layer_id = f"{panel_id}layer"
    bucket_col = f"{panel_id}bucket"
    count_col = f"{panel_id}count"

    add_ref(panel_id, dv_id, layer_id)

    return {
        "version": "8.17.0",
        "type": "lens",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "type": "lens",
                "visualizationType": "lnsXY",
                "state": {
                    "visualization": {
                        "legend": {"isVisible": False},
                        "valueLabels": "show",
                        "preferredSeriesType": "bar_horizontal",
                        "layers": [{
                            "layerId": layer_id,
                            "accessors": [count_col],
                            "xAccessor": bucket_col,
                            "seriesType": "bar_horizontal",
                            "layerType": "data"
                        }]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                layer_id: {
                                    "columns": {
                                        bucket_col: {
                                            "label": label or field.split(".")[-1].replace("_", " ").title(),
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "isBucketed": True,
                                            "scale": "ordinal",
                                            "sourceField": field,
                                            "params": {
                                                "size": size,
                                                "orderBy": {"type": "column", "columnId": count_col},
                                                "orderDirection": "desc"
                                            }
                                        },
                                        count_col: {
                                            "label": "Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "isBucketed": False,
                                            "scale": "ratio",
                                            "sourceField": "___records___"
                                        }
                                    },
                                    "columnOrder": [bucket_col, count_col],
                                    "incompleteColumns": {},
                                    "indexPatternId": dv_id
                                }
                            }
                        }
                    },
                    "adHocDataViews": {}
                },
                "references": [
                    {"type": "index-pattern", "id": dv_id,
                     "name": f"indexpattern-datasource-layer-{layer_id}"}
                ]
            },
            "enhancements": {}
        },
        "title": title
    }


def table_panel(panel_id, title, dv_id, fields, grid, size=20):
    """fields: list of (field, label) or (field, label, dataType) tuples."""
    layer_id = f"{panel_id}layer"
    columns = {}
    col_order = []

    # Find the count column id for orderBy
    count_col_id = None
    for i, item in enumerate(fields):
        field = item[0]
        if field == "___count___":
            count_col_id = f"{panel_id}col{i}"
            break

    for i, item in enumerate(fields):
        field = item[0]
        label = item[1]
        dtype = item[2] if len(item) > 2 else "string"
        col_id = f"{panel_id}col{i}"
        if field == "___count___":
            columns[col_id] = {
                "label": label,
                "dataType": "number",
                "operationType": "count",
                "isBucketed": False,
                "scale": "ratio",
                "sourceField": "___records___"
            }
        else:
            columns[col_id] = {
                "label": label,
                "dataType": dtype,
                "operationType": "terms",
                "isBucketed": True,
                "scale": "ordinal",
                "sourceField": field,
                "params": {
                    "size": size,
                    "orderBy": {"type": "column", "columnId": count_col_id or col_id},
                    "orderDirection": "desc"
                }
            }
        col_order.append(col_id)

    add_ref(panel_id, dv_id, layer_id)

    return {
        "version": "8.17.0",
        "type": "lens",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "type": "lens",
                "visualizationType": "lnsDatatable",
                "state": {
                    "visualization": {
                        "layerId": layer_id,
                        "layerType": "data",
                        "columns": [{"columnId": cid} for cid in col_order]
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                layer_id: {
                                    "columns": columns,
                                    "columnOrder": col_order,
                                    "incompleteColumns": {},
                                    "indexPatternId": dv_id
                                }
                            }
                        }
                    },
                    "adHocDataViews": {}
                },
                "references": [
                    {"type": "index-pattern", "id": dv_id,
                     "name": f"indexpattern-datasource-layer-{layer_id}"}
                ]
            },
            "enhancements": {}
        },
        "title": title
    }


def tagcloud_panel(panel_id, title, dv_id, field, grid, size=30):
    layer_id = f"{panel_id}layer"
    bucket_col = f"{panel_id}bucket"
    count_col = f"{panel_id}count"

    add_ref(panel_id, dv_id, layer_id)

    return {
        "version": "8.17.0",
        "type": "lens",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "type": "lens",
                "visualizationType": "lnsTagcloud",
                "state": {
                    "visualization": {
                        "layerId": layer_id,
                        "tagAccessor": bucket_col,
                        "valueAccessor": count_col,
                        "layerType": "data"
                    },
                    "query": {"query": "", "language": "kuery"},
                    "filters": [],
                    "datasourceStates": {
                        "formBased": {
                            "layers": {
                                layer_id: {
                                    "columns": {
                                        bucket_col: {
                                            "label": "User Agent",
                                            "dataType": "string",
                                            "operationType": "terms",
                                            "isBucketed": True,
                                            "scale": "ordinal",
                                            "sourceField": field,
                                            "params": {
                                                "size": size,
                                                "orderBy": {"type": "column", "columnId": count_col},
                                                "orderDirection": "desc"
                                            }
                                        },
                                        count_col: {
                                            "label": "Count",
                                            "dataType": "number",
                                            "operationType": "count",
                                            "isBucketed": False,
                                            "scale": "ratio",
                                            "sourceField": "___records___"
                                        }
                                    },
                                    "columnOrder": [bucket_col, count_col],
                                    "incompleteColumns": {},
                                    "indexPatternId": dv_id
                                }
                            }
                        }
                    },
                    "adHocDataViews": {}
                },
                "references": [
                    {"type": "index-pattern", "id": dv_id,
                     "name": f"indexpattern-datasource-layer-{layer_id}"}
                ]
            },
            "enhancements": {}
        },
        "title": title
    }


def markdown_panel(panel_id, title, markdown_text, grid):
    return {
        "version": "8.17.0",
        "type": "visualization",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "savedVis": {
                "id": "",
                "title": title,
                "description": "",
                "type": "markdown",
                "params": {
                    "fontSize": 12,
                    "openLinksInNewTab": True,
                    "markdown": markdown_text
                },
                "uiState": {},
                "data": {
                    "aggs": [],
                    "searchSource": {
                        "query": {"query": "", "language": "kuery"},
                        "filter": []
                    }
                }
            },
            "enhancements": {}
        },
        "title": title
    }


def map_panel(panel_id, title, grid):
    # Map references use different naming
    ALL_REFS.append({
        "type": "index-pattern",
        "id": DV_WAZUH,
        "name": f"{panel_id}:layer_1_source_index_pattern"
    })

    return {
        "version": "8.17.0",
        "type": "map",
        "gridData": grid,
        "panelIndex": panel_id,
        "embeddableConfig": {
            "attributes": {
                "title": title,
                "description": "Geographic distribution of attacker IPs",
                "layerListJSON": json.dumps([
                    {
                        "sourceDescriptor": {
                            "type": "EMS_TMS",
                            "isAutoSelect": True
                        },
                        "id": "base-layer",
                        "label": None,
                        "minZoom": 0,
                        "maxZoom": 24,
                        "alpha": 1,
                        "visible": True,
                        "type": "EMS_VECTOR_TILE"
                    },
                    {
                        "sourceDescriptor": {
                            "type": "ES_GEO_GRID",
                            "indexPatternId": DV_WAZUH,
                            "geoField": "GeoLocation.location",
                            "metrics": [{"type": "count"}],
                            "requestType": "point",
                            "resolution": "COARSE"
                        },
                        "id": "wazuh-cluster-layer",
                        "label": "Wazuh Attack Origins",
                        "minZoom": 0,
                        "maxZoom": 24,
                        "alpha": 0.75,
                        "visible": True,
                        "type": "GEOJSON_VECTOR",
                        "style": {
                            "type": "VECTOR",
                            "properties": {
                                "fillColor": {
                                    "type": "DYNAMIC",
                                    "options": {
                                        "field": {"name": "doc_count", "origin": "source"},
                                        "color": "Yellow to Red",
                                        "type": "ORDINAL"
                                    }
                                },
                                "lineColor": {"type": "STATIC", "options": {"color": "#FFFFFF"}},
                                "lineWidth": {"type": "STATIC", "options": {"size": 1}},
                                "iconSize": {
                                    "type": "DYNAMIC",
                                    "options": {
                                        "field": {"name": "doc_count", "origin": "source"},
                                        "minSize": 4,
                                        "maxSize": 32
                                    }
                                },
                                "symbolizeAs": {"options": {"value": "circle"}}
                            }
                        }
                    }
                ]),
                "mapStateJSON": json.dumps({
                    "zoom": 1.5,
                    "center": {"lat": 25, "lon": 10},
                    "timeFilters": {"from": "now-90d", "to": "now"},
                    "refreshConfig": {"isPaused": True, "interval": 0},
                    "query": {"query": "", "language": "kuery"},
                    "filters": []
                }),
                "uiStateJSON": "{}"
            },
            "enhancements": {}
        },
        "title": title
    }


def build_dashboard():
    """Build the complete 15-panel dashboard."""
    global ALL_REFS
    ALL_REFS = []

    markdown_text = """## INST 570 — Honeypot Research Dashboard

### Research Question
_My websites (brianchaplow.com & bytesbourbonbbq.com) run Astro static sites — **not WordPress** — but attackers relentlessly probe them for WordPress vulnerabilities. What can we learn from these attacks?_

### Methodology
- **Honeypot:** Custom wp-login.php trap captures credentials, user agents, and Cloudflare geo headers
- **Wazuh SIEM:** Monitors SSH brute force, web 400 errors, and CMS login attempts on GCP VM
- **Apache Logs:** Raw access logs showing WordPress directory probing
- **Ethical Framework:** All data collected passively from unsolicited attack traffic; no PII of legitimate users

### Data Sources
| Index | Records | Content |
|-------|---------|---------|
| honeypot-credentials | 3,140 | Captured usernames/passwords, geo data, session analysis |
| honeypot-access | 737 | Apache logs showing WordPress probing (paths, status codes) |
| honeypot-wazuh | 5,925 | Wazuh alerts — SSH brute force, web attacks, MITRE mappings |

---
_Brian Chaplow | University of North Alabama | INST 570 | Spring 2026_"""

    panels = []

    # Row 1: Markdown header (full width)
    panels.append(markdown_panel(
        "p1", "Research Overview", markdown_text,
        {"x": 0, "y": 0, "w": 48, "h": 14, "i": "p1"}
    ))

    # Row 2: Four metric panels
    panels.append(metric_panel(
        "p2", "Credential Captures", DV_CREDS, "count",
        grid={"x": 0, "y": 14, "w": 12, "h": 6, "i": "p2"}
    ))
    panels.append(metric_panel(
        "p3", "Wazuh Attack Alerts", DV_WAZUH, "count",
        grid={"x": 12, "y": 14, "w": 12, "h": 6, "i": "p3"}
    ))
    panels.append(metric_panel(
        "p4", "Unique Attacker IPs", DV_WAZUH, "unique_count", field="data.srcip",
        grid={"x": 24, "y": 14, "w": 12, "h": 6, "i": "p4"}
    ))
    panels.append(metric_panel(
        "p5", "Countries Represented", DV_WAZUH, "unique_count", field="GeoLocation.country_name",
        grid={"x": 36, "y": 14, "w": 12, "h": 6, "i": "p5"}
    ))

    # Row 3: Map (full width)
    panels.append(map_panel(
        "p6", "Attacker Origins — Geographic Distribution",
        grid={"x": 0, "y": 20, "w": 48, "h": 18, "i": "p6"}
    ))

    # Row 4: Timeline + Pie (split)
    panels.append(date_histogram_panel(
        "p7", "Attacks Over Time", DV_ALL,
        grid={"x": 0, "y": 38, "w": 30, "h": 14, "i": "p7"}
    ))
    panels.append(pie_panel(
        "p8", "Attack Type Breakdown", DV_WAZUH, "rule.description",
        grid={"x": 30, "y": 38, "w": 18, "h": 14, "i": "p8"}
    ))

    # Row 5: Top URLs + Top Attacker IPs
    panels.append(hbar_panel(
        "p9", "Top Targeted URLs / Paths", DV_ACCESS, "path",
        grid={"x": 0, "y": 52, "w": 24, "h": 14, "i": "p9"}, size=15, label="Path"
    ))
    panels.append(hbar_panel(
        "p10", "Top Attacker IPs", DV_WAZUH, "data.srcip",
        grid={"x": 24, "y": 52, "w": 24, "h": 14, "i": "p10"}, size=15, label="Source IP"
    ))

    # Row 6: Credential analysis — Usernames + Passwords tables
    panels.append(table_panel(
        "p11", "Top Usernames Attempted", DV_CREDS,
        [("credentials.username", "Username"), ("___count___", "Attempts")],
        grid={"x": 0, "y": 66, "w": 24, "h": 14, "i": "p11"}, size=20
    ))
    panels.append(table_panel(
        "p12", "Top Passwords Tried", DV_CREDS,
        [("credentials.password", "Password"), ("___count___", "Attempts")],
        grid={"x": 24, "y": 66, "w": 24, "h": 14, "i": "p12"}, size=20
    ))

    # Row 7: Tag clouds — Usernames + Countries
    panels.append(tagcloud_panel(
        "p16", "Usernames Word Cloud", DV_CREDS, "credentials.username",
        grid={"x": 0, "y": 80, "w": 24, "h": 18, "i": "p16"}, size=40
    ))
    panels.append(tagcloud_panel(
        "p17", "Attacker Countries", DV_WAZUH, "GeoLocation.country_name",
        grid={"x": 24, "y": 80, "w": 24, "h": 18, "i": "p17"}, size=30
    ))

    # Row 8: User agents (bar — strings too long for tag cloud) + MITRE
    panels.append(hbar_panel(
        "p13", "User Agent Fingerprints", DV_CREDS, "source.user_agent.keyword",
        grid={"x": 0, "y": 98, "w": 24, "h": 20, "i": "p13"}, size=15, label="User Agent"
    ))
    panels.append(hbar_panel(
        "p14", "MITRE ATT&CK Techniques", DV_WAZUH, "rule.mitre.technique",
        grid={"x": 24, "y": 98, "w": 24, "h": 20, "i": "p14"}, size=10, label="Technique"
    ))

    # Row 9: Attacker profiles table
    panels.append(table_panel(
        "p15", "Top Attacker Profiles", DV_WAZUH,
        [
            ("data.srcip", "Source IP"),
            ("GeoLocation.country_name", "Country"),
            ("rule.description", "Alert Type"),
            ("___count___", "Alerts"),
        ],
        grid={"x": 0, "y": 118, "w": 48, "h": 16, "i": "p15"}, size=30
    ))

    return panels, ALL_REFS


def main():
    print("Building Honeypot Research Dashboard...")

    panels, refs = build_dashboard()
    panels_json = json.dumps(panels)

    print(f"  {len(panels)} panels, {len(refs)} references")

    # Use direct saved objects API (not import API)
    body = {
        "attributes": {
            "title": "Honeypot Research Dashboard \u2014 INST 570",
            "description": "WordPress honeypot attack analysis across credential captures, Apache access logs, and Wazuh SIEM alerts. Brian Chaplow, UNA INST 570, Spring 2026.",
            "panelsJSON": panels_json,
            "timeRestore": True,
            "timeTo": "now",
            "timeFrom": "now-90d",
            "refreshInterval": {"pause": True, "value": 0},
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": []
                })
            },
            "version": 1
        },
        "references": refs
    }

    url = f"{KIBANA_URL}/api/saved_objects/dashboard/honeypot-research-dashboard"
    creds_str = base64.b64encode(f"{KIBANA_USER}:{KIBANA_PASS}".encode()).decode()

    # Delete existing dashboard first
    try:
        del_req = urllib.request.Request(url, method="DELETE")
        del_req.add_header("kbn-xsrf", "true")
        del_req.add_header("Authorization", f"Basic {creds_str}")
        urllib.request.urlopen(del_req)
        print("  Deleted existing dashboard")
    except Exception:
        pass

    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("kbn-xsrf", "true")
    req.add_header("Authorization", f"Basic {creds_str}")

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
            print(f"  Created dashboard: {result.get('id')}")
    except urllib.error.HTTPError as e:
        err = e.read().decode()
        print(f"  HTTP {e.code}: {err[:1000]}")
        raise

    print(f"\nDashboard URL: {KIBANA_URL}/app/dashboards#/view/honeypot-research-dashboard")

    # Clean up test dashboards
    for test_id in ["test-honeypot", "test-honeypot-2", "test-honeypot-3",
                     "test-honeypot-4", "test-honeypot-5"]:
        try:
            req = urllib.request.Request(
                f"{KIBANA_URL}/api/saved_objects/dashboard/{test_id}",
                method="DELETE"
            )
            req.add_header("kbn-xsrf", "true")
            req.add_header("Authorization", f"Basic {creds_str}")
            urllib.request.urlopen(req)
            print(f"  Cleaned up: {test_id}")
        except Exception:
            pass

    print("Done!")


if __name__ == "__main__":
    main()
