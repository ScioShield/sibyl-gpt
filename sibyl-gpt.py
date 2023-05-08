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

def generate_unique_filename(model, extension="txt"):
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"openai_output_{model}_{timestamp}.{extension}"

def save_output_to_file(output, file_name):
    with open(file_name, "w") as file:
        file.write(output)

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

def get_user_choice(alert_options, debug, model):
    user_choice = ""

    while True:
        user_choice = input(f"> Enter the number of the alert you'd like to investigate (1-{len(alert_options)}), 'H' for hint (sends the alert selection to OpenAI) or 'Q' to quit: ").strip()

        if user_choice.lower() == "q":
            print("Quitting the script. Bye!")
            sys.exit(0)

        if user_choice.lower() == "h":
            hint_prompt = "Thinking step by step which option is the best to investigate among the following alerts?\n"
            for i, option in enumerate(alert_options, start=1):
                hint_prompt += f"{i}. {option.get('kibana.alert.rule.name')}, Severity: {option.get('kibana.alert.severity')}, Description: {option.get('kibana.alert.reason')}\n"
            hint = call_openai_api(hint_prompt, "", debug, model)
            cost = string_cost(hint_prompt, model)
            print(f"Hint: {hint}")
            print(f"\nTotal estimated cost for hint API call: ${cost:.4f}")
            continue

        try:
            user_choice = int(user_choice)
            if 1 <= user_choice <= len(alert_options):
                chosen_alert = alert_options[user_choice - 1]
                return chosen_alert
            else:
                print(f"Please choose a number between 1 and {len(alert_options)}")
        except ValueError:
            print("Invalid input. Please enter a number, 'H' for hint or 'Q' to quit.")

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

def call_openai_api(prompt, event, debug, model):
    if debug:
        print("OpenAI API request:")
        print(f"Model: {model}")
        print(f"Messages: {prompt}\n{event}")
        return "Debug mode: Skipping API call"

    completion = openai.ChatCompletion.create(
        model=model,
        messages=[{"role": "user", "content": f"{prompt}\n{event}"}]
    )

    summary = completion['choices'][0]['message']["content"]
    return summary

def main():
    args = parse_arguments()
    openai_input_output = ""
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

    prompts = [
    "Thinking step by step create an investigation and remediation for the alert:",
    "Thinking step by step create and justify Kibana searches to investigate this incident:"
    ]

    if args.debug:
        print("Status code:", response.status_code)

    alert_options = display_alert_options(unique_alerts, fields)
    chosen_alert = get_user_choice(alert_options, args.debug, model)
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
    chosen_filtered_alert = get_user_choice(filtered_alert_options, args.debug, model)
    
    total_cost = 0

    for prompt in prompts:
        summary = call_openai_api(prompt, chosen_filtered_alert, args.debug, model)
        input_string = f"{prompt}\n{chosen_filtered_alert}"
        cost = string_cost(input_string, model)
        total_cost += cost
        print(f"\n{prompt}\n")
        
        # Use rich to render the summary with Markdown formatting
        rich_summary = Markdown(summary)
        rprint(rich_summary)
        
        openai_input_output += f"\nModel: {model}\n"
        openai_input_output += f"\nMessages: {chosen_filtered_alert}\n"
        openai_input_output += f"\n{prompt}\n{summary}\n"
    
    print(f"\nTotal estimated cost for all API calls: ${total_cost:.4f}")

    if args.save:
        output_file = generate_unique_filename(model)
        save_output_to_file(openai_input_output, output_file)
        print(f"\nThe OpenAI output and inputs have been saved to {output_file}")

if __name__ == "__main__":
    main()