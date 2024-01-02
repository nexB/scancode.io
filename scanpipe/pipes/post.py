import json

from django.core.serializers.json import DjangoJSONEncoder

import requests


def test_json_post_accepting_urls(urls=[]):
    if not urls:
        return []
    # define test payload
    payload = {"name": "test"}
    errors = []
    if isinstance(urls, str):
        urls = [url.strip() for url in urls.split()]

    for url in urls:
        if not url:
            continue
        try:
            response = requests.post(
                url=url,
                data=json.dumps(payload, cls=DjangoJSONEncoder),
                headers={"Content-Type": "application/json"},
                timeout=10,
            )
            # Raise an HTTPError for bad responses (4xx or 5xx)
            response.raise_for_status()
        except requests.exceptions.RequestException:
            errors.append(url)

    return errors
