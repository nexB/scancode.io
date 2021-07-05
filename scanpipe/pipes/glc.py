import io
import json
from os.path import abspath
from os.path import expanduser
from os.path import isfile
from os.path import normpath

from commoncode.resource import get_path
from LicenseClassifier.classifier import LicenseClassifier

from scanpipe.models import CodebaseResource


def run_glc(location, output_file):
    """
    Scan `location` content and write results into `output_file`.
    """
    classifier = LicenseClassifier()
    _ = classifier.analyze(location, output=output_file)
    return


def to_dict(location):
    """
    Return scan data loaded from `location`, which is a path string
    """
    try:
        location = abspath(normpath(expanduser(location)))
        with io.open(location, "rb") as f:
            scan_data = json.load(f)
        return scan_data

    except IOError:
        # Raise Some Error perhaps
        raise ValueError


def create_codebase_resources(project, scan_data):
    resource_data = {}
    root = scan_data["headers"][0]["input"]
    for scanned_resource in scan_data["files"]:
        for field in CodebaseResource._meta.fields:

            if field.name == "path":
                continue

            elif field.name == "copyrights":
                value = [
                    {"value": record.pop("expression", None), **record}
                    for record in scanned_resource.get("copyrights", [])
                ]

            elif field.name == "holders":
                value = [
                    {
                        "value": record.pop("holder", None),
                        "start_index": record.pop("start_index", None),
                        "end_index": record.pop("end_index", None),
                    }
                    for record in scanned_resource.get("copyrights", [])
                ]

            else:
                value = scanned_resource.get(field.name, None)

            if value is not None:
                resource_data[field.name] = value

        resource_type = "FILE" if isfile(scanned_resource["path"]) else "DIRECTORY"
        resource_data["type"] = CodebaseResource.Type[resource_type]
        resource_path = get_path(root, scanned_resource["path"], strip_root=True)

        _, flag = CodebaseResource.objects.get_or_create(
            project=project,
            path=resource_path,
            defaults=resource_data,
        )
