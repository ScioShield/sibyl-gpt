import requests
import uuid
import openai
import os
import argparse
from dotenv import load_dotenv
import sys
from datetime import datetime
from rich import print as rprint
from rich.markdown import Markdown

def parse_arguments():
    parser = argparse.ArgumentParser(description="Sibyl-GPT alert parsing script")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode, doesn't send any API calls to OpenAI")
    parser.add_argument("--g4", action="store_true", help="Use gpt-4 model, defaults to gpt-3.5-turbo")
    parser.add_argument("--risk", type=int, default=70, help="Specify the minimum risk score (0-100), defaults to 70")
    parser.add_argument("--size", type=int, default=100, help="Specify the number of returned results (the unique_alerts search is separate), defaults to 100")
    parser.add_argument("--save", action="store_true", help="Save the OpenAI output to a file, doesn't work for hints")
    args = parser.parse_args()
    return args

class Session:
    def __init__(self):
        self.data = ""
        self.total_cost = 0  # Tracks total cost of API calls

    def add_input_output(self, model, prompt, event, summary, cost):
        self.data += f"\nModel: {model}\n"
        self.data += f"\nMessages: {event}\n"
        self.data += f"\n{prompt}\n{summary}\n"
        self.data += f"\nCost: {cost:.4f}\n"  # Update total cost with the cost of the current API call

    def save_to_file(self, model, extension="txt"):
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        file_name = f"openai_output_{model}_{timestamp}.{extension}"
        with open(file_name, "w") as file:
            file.write(self.data)
        return file_name

def generate_unique_filename(model, extension="txt"):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"openai_output_{model}_{timestamp}.{extension}"

def extract_fields(nested_dict, fields, prefix=""):
    new_dict = {}
    for key, value in nested_dict.items():
        current_key = f"{prefix}.{key}" if prefix else key
        if current_key in fields:
            new_dict[current_key] = value
        elif isinstance(value, dict):
            extracted = extract_fields(value, fields, prefix=current_key)
            if extracted:
                new_dict.update(extracted)
    return new_dict

def setup_api_credentials():
    load_dotenv()
    es_url = os.getenv("E_URL")
    es_username = os.getenv("E_USER")
    es_password = os.getenv("E_PASS")
    CA_CERTS_PATH = os.getenv("E_CA_PATH")
    openai_key = os.getenv("OPENAI_API_KEY")
    openai.api_key = openai_key
    return es_url, es_username, es_password, CA_CERTS_PATH

def send_post_request(es_url, es_username, es_password, CA_CERTS_PATH, body):
    headers = {"Content-Type": "application/json", "kbn-xsrf": str(uuid.uuid4())}
    response = requests.post(
        url=f"{es_url}/api/detection_engine/signals/search",
        json=body,
        headers=headers,
        auth=(es_username, es_password),
        verify=CA_CERTS_PATH
    )
    return response

def display_alert_options(unique_alerts, fields):
    alert_options = []

    for index, alert_bucket in enumerate(unique_alerts):
        top_alert = alert_bucket.get("top_alerts", {}).get("hits", {}).get("hits", [])

        if top_alert:
            top_alert = top_alert[0]
            event = extract_fields(top_alert["_source"], fields)
            alert_options.append(event)
            print(f"[{index + 1}] {event.get('kibana.alert.rule.name')}, Severity: {event.get('kibana.alert.severity')}")

    return alert_options

def get_user_choice(alert_options, debug, model, session, first_choice=True):
    user_choice = ""

    while True:
        user_choice = input(f"> Enter the number of the alert you'd like to investigate (1-{len(alert_options)}), 'H' for hint (sends the alert selection to OpenAI), 'E' followed by a number (e.g., 'E 1') or 'E H' for cost estimate, or 'Q' to quit: ").strip()

        if user_choice.lower() == "q":
            print("Quitting the script. Bye!")
            sys.exit(0)

        if user_choice.lower() == "h":
            hint_prompt = "Thinking step by step which option is the best to investigate among the following alerts?\n"
            for i, option in enumerate(alert_options, start=1):
                hint_prompt += f"{i}. {option.get('kibana.alert.rule.name')}, Severity: {option.get('kibana.alert.severity')}, Description: {option.get('kibana.alert.reason')}\n"
            hint = call_openai_api(hint_prompt, "", debug, model, session)
            cost = string_cost(hint_prompt, model)
            print(f"Hint: {hint}")
            print(f"\nTotal estimated cost for hint API call: ${cost:.4f}")
            continue

        if user_choice.lower().startswith("e "):
            user_choice = user_choice[2:]
            try:
                if user_choice.lower() == "h":
                    estimate_prompt = "Thinking step by step which option is the best to investigate among the following alerts?\n"
                    for i, option in enumerate(alert_options, start=1):
                        estimate_prompt += f"{i}. {option.get('kibana.alert.rule.name')}, Severity: {option.get('kibana.alert.severity')}, Description: {option.get('kibana.alert.reason')}\n"
                    cost = string_cost(estimate_prompt, model)
                    print(f"\nTotal estimated cost for the hint API call: ${cost:.4f}")
                else:
                    user_choice = int(user_choice)
                    if 1 <= user_choice <= len(alert_options):
                        if first_choice:
                            print("The first selection screen is always free. There is no cost associated with it.")
                            continue
                        chosen_alert = alert_options[user_choice - 1]
                        estimate_prompt, cost = process_prompts(chosen_alert, model, session, debug=True, print_output=False)
                        cost = string_cost(estimate_prompt, model)
                    else:
                        raise ValueError
                continue
            except ValueError:
                print("Invalid input. Please enter a number, 'H' for hint, 'E' followed by a number (e.g., 'E 1') or 'E H' for cost estimate, or 'Q' to quit.")

        try:
            user_choice = int(user_choice)
            if 1 <= user_choice <= len(alert_options):
                chosen_alert = alert_options[user_choice - 1]
                return chosen_alert
            else:
                print(f"Please choose a number between 1 and {len(alert_options)}")
        except ValueError:
            print("Invalid input. Please enter a number, 'H' for hint, 'E' followed by a number (e.g., 'E 1') or 'E H' for cost estimate, or 'Q' to quit.")

def display_filtered_alerts(alerts, chosen_uuid, fields):
    filtered_alert_options = []

    for index, alert in enumerate(alerts):
        event = extract_fields(alert["_source"], fields)

        if event.get("kibana.alert.rule.rule_id") == chosen_uuid:
            filtered_alert_options.append(event)
            print(f"[{index + 1}] {event.get('kibana.alert.rule.name')}, Severity: {event.get('kibana.alert.severity')}, Description: {event.get('kibana.alert.reason')}")

    return filtered_alert_options

def string_cost(string, model):
    token_cost = 0

    if model == "gpt-4":
        token_cost = 0.06
    elif model == "gpt-3.5-turbo":
        token_cost = 0.002
    else:
        return "Invalid model type"

    tokens = len(string.split())
    tokens_1k = tokens / 750
    cost = tokens_1k * token_cost
    return cost

def call_openai_api(prompt, event, debug, model, session):
    input_string = f"{prompt}\n{event}"
    cost = string_cost(input_string, model)
    session.total_cost += cost
    if debug:
        print("OpenAI API request:")
        print(f"Model: {model}")
        print(f"Messages: {input_string}")
        
        # Update session with input and output (for debug mode)
        debug_summary = "Debug mode: Skipping API call"
        session.add_input_output(model, prompt, event, debug_summary, cost)

        return debug_summary

    completion = openai.ChatCompletion.create(
        model=model,
        messages=[{"role": "user", "content": input_string}]
    )

    summary = completion['choices'][0]['message']["content"]

    # Update session with input and output
    session.add_input_output(model, prompt, event, summary, cost)

    return summary

def dummy_call_openai_api(prompt, event, model, session, debug, print_output):
    input_string = f"{prompt}\n{event}"
    cost = string_cost(input_string, model)
    session.total_cost += cost
    if debug and print_output:
        print("Dummy OpenAI API request:")
        print(f"Model: {model}")
        print(f"Messages: {input_string}")

    # Update session with input and output (for debug mode)
    debug_summary = "Debug mode: Skipping API call"
    session.add_input_output(model, prompt, event, debug_summary, cost)

    return debug_summary

def process_prompts(chosen_filtered_alert, model, session, debug, print_output=True):
    
    prompts = [
    "Thinking step by step create an investigation and remediation for the alert:",
    "Thinking step by step create and justify Kibana searches to investigate this incident:"
    ]

    e_total_cost = 0

    for prompt in prompts:
        if debug:
            summary = dummy_call_openai_api(prompt, chosen_filtered_alert, model, session, debug, print_output)
        else:
            summary = call_openai_api(prompt, chosen_filtered_alert, debug, model, session)
        input_string = f"{prompt}\n{chosen_filtered_alert}"
        cost = string_cost(input_string, model)
        e_total_cost += cost
        if print_output:
            print(f"\n{prompt}\n")

            # Use rich to render the summary with Markdown formatting
            rich_summary = Markdown(summary)
            rprint(rich_summary)
    
    print(f"\nTotal estimated cost for these API calls: ${e_total_cost:.4f}")

    return input_string, e_total_cost

def main():
    args = parse_arguments()
    session = Session()  # Create a new Session object

    model = "gpt-4" if args.g4 else "gpt-3.5-turbo"

    if not 0 <= args.risk <= 100:
        print("Error: Risk score should be between 0 and 100.")
        sys.exit(1)

    if not 1 <= args.size:
        print("Error: Size should be above 0.")
        sys.exit(1)
    
    es_url, es_username, es_password, CA_CERTS_PATH = setup_api_credentials()

    body = {
      "aggs": {
        "unique_alerts": {
          "terms": {
            "field": "kibana.alert.rule.name",
            "size": 1000,
            "order": {
              "max_severity_score": "desc"
            }
          },
          "aggs": {
            "max_severity_score": {
              "max": {
                "field": "signal.rule.risk_score"
              }
            },
            "top_alerts": {
              "top_hits": {
                "size": 1
              }
            }
          }
        },
        "latest": {
          "max": {
            "field": "@timestamp"
          }
        },
        "oldest": {
          "min": {
            "field": "@timestamp"
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "match": {
                "signal.status": "open"
              }
            },
            {
              "range": {
                "signal.rule.risk_score": {
                  "gte": args.risk
                }
              }
            }
          ]
        }
      },
      "size": args.size
    }
    
    response = send_post_request(es_url, es_username, es_password, CA_CERTS_PATH, body)
    
    unique_alerts = response.json().get("aggregations", {}).get("unique_alerts", {}).get("buckets", [])

    fields = [
        "kibana.alert.start",
        "kibana.alert.severity",
        "kibana.alert.rule.name",
        "kibana.alert.rule.description",
        "kibana.alert.reason",
        "kibana.alert.risk_score",
        "kibana.alert.rule.threat",
        "kibana.alert.rule.rule_id",
        "host",
        "process.args"
    ]

    if args.debug:
        print("Status code:", response.status_code)
        print("Connecting to: ", es_url)

    alert_options = display_alert_options(unique_alerts, fields)
    chosen_alert = get_user_choice(alert_options, args.debug, model, session, first_choice=True)
    chosen_uuid = chosen_alert.get("kibana.alert.rule.rule_id")

    body2 = {
      "aggs": {
        "latest": {
          "max": {
            "field": "@timestamp"
          }
        },
        "oldest": {
          "min": {
            "field": "@timestamp"
          }
        }
      },
      "query": {
        "bool": {
          "filter": [
            {
              "match": {
                "kibana.alert.rule.rule_id": chosen_uuid
              }
            }
          ]
        }
      },
      "sort": [
        {
          "@timestamp": {
            "order": "asc"
          }
        }
      ],
      "size": args.size
    }

    response2 = send_post_request(es_url, es_username, es_password, CA_CERTS_PATH, body2)
    new_alerts = response2.json().get("hits", {}).get("hits", [])

    filtered_alert_options = display_filtered_alerts(new_alerts, chosen_uuid, fields)
    chosen_filtered_alert = get_user_choice(filtered_alert_options, args.debug, model, session, first_choice=False)

    process_prompts(chosen_filtered_alert, model, session, args.debug)
    print(f"\nTotal estimated cost for all API calls: ${session.total_cost:.4f}")

    if args.save:
        output_file = session.save_to_file(model)  # Save session data to a file
        print(f"\nThe OpenAI output and inputs have been saved to {output_file}")

if __name__ == "__main__":
    main()