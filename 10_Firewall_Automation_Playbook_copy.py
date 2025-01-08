"""
Accepts Url and does reputation analysis on the object.  The reputation analysis can help detect and prevent potential malware attacks by analyzing the trustworthiness of the url. This playbook is used for request, that come in when users cannot access speicific websites.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'input_filter' block
    input_filter(container=container)

    return

@phantom.playbook_block()
def format_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_output() called")

    template = """###REQUEST INFO\n\nUser: user@grenke\nUser Comment: \"test\"\nUrl Category: command-and-control\n\n###ANALYSIS RESULT\n---------------\n[Alienvault] \n\n\n[Virustotal]\n\n\nSOAR analyzed URL(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n| `http://www.releasingpotential.com/` | Very_Safe | ['service and philanthropic organizations', 'media sharing'] | https://www.virustotal.com/gui/url/27c150dec12f85bccde8fd76f2d794bfa24b51e82534bacb0be8e737e350e966\n | VirusTotal v3 |\n\nSOAR analyzed Domain(s) using VirusTotal.  The table below shows a summary of the information gathered.\n\n| Domain | Normalized Data | Categories | Report Link | Source |\n| --- | --- | --- | --- | --- |\n| `www.releasingpotential.com` | Very_Safe | [] | https://www.virustotal.com/gui/domain/www.releasingpotential.com | VirusTotal v3 |\n\n\n[Urlscan] \n\n\nSOAR analyzed URL(s) using urlscan.io.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Confidence | Categories | Report Link | \n| --- | --- | --- | --- | --- |\n| `http://www.releasingpotential.com/` | Safe | 0.0 | [] |https://urlscan.io/result/1746ac89-20d0-40a7-bfa9-50037b09565d/ |\n\n[SAA]\n\nSOAR analyzed URL(s) using Splunk Attack Analyzer.  The table below shows a summary of the information gathered.\n\n| URL | Normalized Score | Score Id | Classifications | Report Link | Source |\n| --- | --- | --- | --- | --- | --- |\n| `http://www.releasingpotential.com/` | Unknown | 0 | ['Unknown'] | https://app.eu1.twinwave.io/job/19452bb3-ca01-4a75-88ee-c1c8c9356a89 | Splunk Attack Analyzer (SAA) |\n\nScreenshots associated with the detonated URLs are shown below (if available):\n\n#### http://www.releasingpotential.com/\n![Splunk Attack Analyzer screenshot 19452bb3-ca01-4a75-88ee-c1c8c9356a89 #0.png](/view?id=3056)\n![Splunk Attack Analyzer screenshot 19452bb3-ca01-4a75-88ee-c1c8c9356a89 #1.png](/view?id=3057)\n![Splunk Attack Analyzer screenshot 19452bb3-ca01-4a75-88ee-c1c8c9356a89 #2.png](/view?id=3058)\n![Splunk Attack Analyzer screenshot 19452bb3-ca01-4a75-88ee-c1c8c9356a89 #3.png](/view?id=3059)\n![Splunk Attack Analyzer screenshot 19452bb3-ca01-4a75-88ee-c1c8c9356a89 #4.png](/view?id=3060)\n\n, """

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_output", drop_none=True)

    soc_analyst_decision(container=container)

    return


@phantom.playbook_block()
def soc_analyst_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("soc_analyst_decision() called")

    # set approver and message variables for phantom.prompt call

    saml_group = [
        "b3f71e0f-b0c7-49a4-acb6-2e88827f9846",
        "b6d7424e-4517-42e3-bed3-b8bc51e3bad6"
    ]
    message = """{0}\n"""

    # parameter list for template variable replacement
    parameters = [
        "format_output:formatted_data"
    ]

    # responses
    response_types = [
        {
            "prompt": "Accept, decline or delegate Firewall request?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Accept",
                    "Decline",
                    "Delegate"
                ],
            },
        },
        {
            "prompt": "Reason for Action (When declining, comment is sent to user!)",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, saml_required=True, saml_group=saml_group, message=message, respond_in_mins=129600, name="soc_analyst_decision", parameters=parameters, response_types=response_types, callback=analyst_decision_result_filter, dispatch_callback=soc_analyst_decision_dispatch_callback)

    return


@phantom.playbook_block()
def soc_analyst_decision_dispatch_callback(container=None):
    phantom.debug("soc_analyst_decision_dispatch_callback() called")

    
    send_email_3(container=container)


    return


@phantom.playbook_block()
def analyst_decision_result_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("analyst_decision_result_filter() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["soc_analyst_decision:action_result.summary.responses.0", "==", "Accept"]
        ],
        name="analyst_decision_result_filter:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pass

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["soc_analyst_decision:action_result.summary.responses.0", "==", "Decline"]
        ],
        name="analyst_decision_result_filter:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_comment_14(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    # collect filtered artifact ids and results for 'if' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        conditions=[
            ["soc_analyst_decision:action_result.summary.responses.0", "==", "Delegate"]
        ],
        name="analyst_decision_result_filter:condition_3",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_3 or matched_results_3:
        grenke_analyst_decision(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)
        add_comment_15(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_3, filtered_results=matched_results_3)

    return


@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("input_filter() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", ""]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_http(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_http(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_http() called")

    ################################################################################
    # Adds "http://" to url if its missing to correctly analyse the url in the playbooks.
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.requestURL"])

    container_artifact_cef_item_0 = [item[0] for item in container_artifact_data]

    add_http__add_http = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    add_http__add_http = []
    for url in container_artifact_cef_item_0:
        if not url.startswith("http://") and not url.startswith("https://"):
            add_http__add_http.append("http://" + url)
        else:
            add_http__add_http.append(url)
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="add_http:add_http", value=json.dumps(add_http__add_http))

    extract_domain(container=container)

    return


@phantom.playbook_block()
def extract_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("extract_domain() called")

    ################################################################################
    # Extracts domain from url.
    ################################################################################

    add_http__add_http = json.loads(_ if (_ := phantom.get_run_data(key="add_http:add_http")) != "" else "null")  # pylint: disable=used-before-assignment

    extract_domain__domain = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from urllib.parse import urlparse
    extract_domain__domain = urlparse(add_http__add_http[0]).netloc

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="extract_domain:domain", value=json.dumps(extract_domain__domain))

    format_output(container=container)

    return


@phantom.playbook_block()
def join_close_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("join_close_event() called")

    if phantom.completed(action_names=["grenke_analyst_decision", "soc_analyst_decision"]):
        # call connected block "close_event"
        close_event(container=container, handle=handle)

    return


@phantom.playbook_block()
def close_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("close_event() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_status(container=container, status="closed")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def send_email_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("send_email_3() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    body_formatted_string = phantom.format(
        container=container,
        template="""<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\"><html xmlns=\"http://www.w3.org/1999/xhtml\" xmlns:o=\"urn:schemas-microsoft-com:office:office\"><head><meta charset=\"UTF-8\"><meta content=\"width=device-width, initial-scale=1\" name=\"viewport\"><meta name=\"x-apple-disable-message-reformatting\"><meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"><meta content=\"telephone=no\" name=\"format-detection\"><title></title><!--[if (mso 16)]><style type=\"text/css\">a {{text-decoration: none;}}</style><![endif]--><!--[if gte mso 9]><style>sup {{font-size: 100% !important;}}</style><![endif]--><!--[if gte mso 9]><style>img.header {{width: 55px}}</style><![endif]--><!--[if gte mso 9]><xml><o:OfficeDocumentSettings><o:AllowPNG></o:AllowPNG><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]--></head><body><div class=\"es-wrapper-color\"><!--[if gte mso 9]><v:background xmlns:v=\"urn:schemas-microsoft-com:vml\" fill=\"t\"><v:fill type=\"tile\" color=\"#ffffff\"></v:fill></v:background><![endif]--><table class=\"es-wrapper\" width=\"100%\" cellspacing=\"0\" cellpadding=\"0\"><tbody><tr><td class=\"esd-email-paddings\" valign=\"top\"><table cellpadding=\"0\" cellspacing=\"0\" class=\"es-content esd-header-popover\" align=\"center\"><tbody><tr><td class=\"esd-stripe\" align=\"center\"><table bgcolor=\"#ffffff\" class=\"es-content-body\" align=\"center\" cellpadding=\"0\"   cellspacing=\"0\" width=\"700\"><tbody><tr><td class=\"es-p20t es-p20r es-p20l esd-structure\" align=\"left\"><table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tbody><tr><td width=\"660\" class=\"esd-container-frame\" align=\"center\" valign=\"top\"><table cellpadding=\"5\" cellspacing=\"0\" width=\"100%\"><tbody><tr><td align=\"right\" class=\"esd-block-text\" bgcolor=\"#58817b\"><img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHMAAAD6CAYAAACS/Hj2AAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAAZdEVYdFNvZnR3YXJlAEFkb2JlIEltYWdlUmVhZHlxyWU8AAAECGlUWHRYTUw6Y29tLmFkb2JlLnhtcAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgOS4xLWMwMDEgNzkuMTQ2Mjg5OTc3NywgMjAyMy8wNi8yNS0yMzo1NzoxNCAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wTU09Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9tbS8iIHhtbG5zOnN0UmVmPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvc1R5cGUvUmVzb3VyY2VSZWYjIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1wTU06T3JpZ2luYWxEb2N1bWVudElEPSJ4bXAuZGlkOjhlMmM4YTc0LWJiYjQtNGExMC05ZmVhLTU5NGIyZjFkNjQzMSIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpCMjkwMTIyQkM4MjExMUVFOUVDOUEzQzZDQ0FDNTNBQSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpCMjkwMTIyQUM4MjExMUVFOUVDOUEzQzZDQ0FDNTNBQSIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBJbGx1c3RyYXRvciAyNy45IChNYWNpbnRvc2gpIj4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InV1aWQ6ZDE1ZTli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\"></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table><table cellpadding=\"0\" cellspacing=\"0\" class=\"es-content esd-footer-popover\" align=\"center\"><tbody><tr><td class=\"esd-stripe\" align=\"center\"><table bgcolor=\"#ffffff\" class=\"es-content-body\" align=\"center\" cellpadding=\"0\"   cellspacing=\"0\" width=\"700\"><tbody><tr><td class=\"esd-structure es-p20r es-p20l\" align=\"left\"><table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tbody><tr><td width=\"660\" class=\"esd-container-frame\" align=\"center\" valign=\"top\"><table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tbody><tr><td align=\"left\" class=\"esd-block-text\"style=\"padding-left:10px; background-color: #f5fffd;\"><p style=\"color: black; font-family: 'Arial', 'Helvetica', Sans-Serif; font-size: 26px; margin-top: 26px; margin-bottom: 0\">Firewall Exception Requested</p></td></tr></tbody></table></td></tr></tbody></table></td></tr><tr><td class=\"esd-structure es-p20r es-p20l\" align=\"left\"><table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tbody><tr><td width=\"660\" class=\"esd-container-frame\" align=\"center\" valign=\"top\"><table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tbody><tr><td style=\"background-color: #f5fffd; font-family: 'Arial', 'Helvetica', Sans-Serif; padding-left:10px\"align=\"left\" class=\"esd-block-text\"><p style=\"margin: 0\"><br><br>Hello SOC Team,<br><br>You have been assigned an action 'analyst_decision'.<br><br>To execute the requested action, deny or delegate, click here:<br><br>{0}<br><br>Kind Regards<br>Security-Team<br><br></p></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></table></div></body></html>""",
        parameters=[
            "soc_analyst_decision:action_result.parameter.secure_link"
        ])

    soc_analyst_decision_result_data = phantom.collect2(container=container, datapath=["soc_analyst_decision:action_result.parameter.secure_link","soc_analyst_decision:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'send_email_3' call
    for soc_analyst_decision_result_item in soc_analyst_decision_result_data:
        if body_formatted_string is not None:
            parameters.append({
                "cc": "",
                "to": "mariocasimirogafas@mariocasimirogafas.onmicrosoft.com",
                "bcc": "",
                "body": body_formatted_string,
                "from": "mokularczyk@splunk.com",
                "subject": "Firewall Exception Requested",
                "context": {'artifact_id': soc_analyst_decision_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email_3", assets=["localsmtp"])

    return


@phantom.playbook_block()
def grenke_analyst_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("grenke_analyst_decision() called")

    # set approver and message variables for phantom.prompt call

    user = None
    role = "Analyst Decision"
    message = """SOC Comment:\n{1}\n-------------\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "format_output:formatted_data",
        "soc_analyst_decision:action_result.summary.responses.1"
    ]

    # responses
    response_types = [
        {
            "prompt": "Accept or decline Firewall request?",
            "options": {
                "type": "list",
                "required": True,
                "choices": [
                    "Accept",
                    "Decline"
                ],
            },
        },
        {
            "prompt": "Reason for Declining (sent to user)",
            "options": {
                "type": "message",
                "required": True,
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=129600, name="grenke_analyst_decision", parameters=parameters, response_types=response_types, callback=filter_2)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["grenke_analyst_decision:action_result.summary.responses.0", "==", "Accept"]
        ],
        name="filter_2:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_comment_11(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["grenke_analyst_decision:action_result.summary.responses.0", "==", "Decline"]
        ],
        name="filter_2:condition_2",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_comment_5(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def add_comment_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_5() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Grenke declined firewall request")

    join_close_event(container=container)

    return


@phantom.playbook_block()
def add_comment_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_11() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Grenke accepted request")

    join_close_event(container=container)

    return


@phantom.playbook_block()
def add_comment_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_14() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="soc decline")

    join_close_event(container=container)

    return


@phantom.playbook_block()
def add_comment_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_comment_15() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="soc accept")

    join_close_event(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return