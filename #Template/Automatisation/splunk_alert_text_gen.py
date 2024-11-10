# Installez les bibliothèques suivantes pour exécuter ce script : splunk-sdk, splunklib, jinja2
import splunklib.client as client
from jinja2 import Template
import json
import datetime


# Connexion à Splunk
service = client.connect(
    host='172.10.80.216',
    port='8089',
    scheme='https',
    username='ayoub',
    password='azerty12'
)

# Requête de recherche Splunk
search_query = 'search index=alerts event.event_title="*" (event.impact="critical" OR event.impact="high") earliest=-24h'

# Envoi de la requête de recherche à Splunk
search_results = service.jobs.oneshot(search_query, output_mode='json')
# Récupération des résultats de la recherche au format JSON
jsout = json.loads(search_results.read())


# Process each result to parse the _raw field as JSON
for result in jsout['results']:
    try:
        # Convert _raw to a dictionary if it's a JSON string
        raw_data = json.loads(result['_raw'])
        # Extract fields from the parsed _raw data
        result['description'] = raw_data.get('event', {}).get('originQuery', {}).get('description', 'No description available')
    except json.JSONDecodeError:
        # If _raw is not valid JSON, handle the error
        result['description'] = 'No description available'

# Jinja2 template for notification in Markdown
template = """
{% for result in jsout['results'] %}
# Alerte : *[{{ result['event.impact'] }}]* {{ result['event.event_title'] }}
    Description : {{ result['description'] }}
    Horodatage : {{ datetime.datetime.fromisoformat(result['_time']) }}
{% endfor %}
"""

# Initialize Jinja template
jinja_template = Template(template)

# Render template with Splunk data
print(jinja_template.render(jsout=jsout, datetime=datetime))

# Logout from Splunk
service.logout()