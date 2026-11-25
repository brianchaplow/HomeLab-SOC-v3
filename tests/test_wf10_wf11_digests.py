"""WF10 Morning Briefing and WF11 Evening Digest: the compose_message LLM call.

Ollama 0.35 ignores the /no_think prompt prefix. Without "think": false in the
request body qwen3 reasons before it answers, which more than doubles the run
time and is what pushed the evening digest past its 180s timeout
("LLM unavailable: timed out").
"""
import pytest

from shuffle_harness import MockLab, http_body, run_node, upstream

SECTIONS = {
    "security_data": "Alerts: 120 (0 crit, 3 high) | Open Cases: 1 | Top Rule: sshd auth failure",
    "infra_data": "Hosts: 5/5 HEALTHY | Services: 21/21 UP | Disk Watch: brisket (41%)",
    "projects_data": "Capitol Signals: OK",
    "websites_data": "brianchaplow.com: UP (131ms) | Internal services: 14/14 UP",
    "overnight_data": "Threat Intel IOCs synced: 310 | No high-score ML events",
}
HACCP = {"stats_line": "HACCP: 10 events, 0 TI match, 5 novel",
         "embed": {"title": "HACCP tier 2", "description": "nominal"}}

DIGESTS = {
    "wf10-morning-briefing.json": ["security_data", "infra_data", "overnight_data"],
    "wf11-evening-digest.json": ["security_data", "infra_data", "projects_data", "websites_data",
                                 "overnight_data"],
}


@pytest.fixture
def lab_factory():
    labs = []

    def make(script):
        lab = MockLab(script)
        labs.append(lab)
        return lab

    yield make
    for lab in labs:
        lab.close()


def compose(filename, lab):
    results = [upstream(label, {"section": SECTIONS[label]}) for label in DIGESTS[filename]]
    if filename.startswith("wf10"):
        results.append(upstream("haccp_briefing", HACCP))
    result, _ = run_node(filename, "compose_message", {"ollama_url": lab.url}, results)
    return result, http_body(filename, "discord_send", {"compose_message": result})["content"]


@pytest.mark.parametrize("filename", DIGESTS)
def test_compose_message_turns_thinking_off(lab_factory, filename):
    lab = lab_factory([("ok", "Security: 120 alerts, 3 high. Watch: verified 5/5 hosts healthy.")])
    _, content = compose(filename, lab)

    assert "__Watch Officer Assessment__\nSecurity: 120 alerts, 3 high." in content
    assert len(lab.requests) == 1
    assert lab.requests[0]["think"] is False
    assert lab.requests[0]["prompt"].startswith("/no_think ")


@pytest.mark.parametrize("filename", DIGESTS)
def test_retry_after_an_empty_reply_also_turns_thinking_off(lab_factory, filename):
    lab = lab_factory([("ok", "<think>only reasoning</think>"), ("ok", "Security: fine.")])
    _, content = compose(filename, lab)

    assert "Security: fine." in content
    assert [r["think"] for r in lab.requests] == [False, False]


@pytest.mark.parametrize("filename", DIGESTS)
def test_hostile_reply_keeps_the_discord_body_valid(lab_factory, filename):
    lab = lab_factory([("ok", 'Security: "quoted" C:\\Temp\tpath.\nWatch: none.')])
    _, content = compose(filename, lab)  # http_body raises on invalid JSON

    assert "Security: 'quoted' C:Temp path. Watch: none." in content
