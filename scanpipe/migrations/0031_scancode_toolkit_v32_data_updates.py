# Generated by Django 4.2 on 2023-05-05 10:11

from django.db import migrations
from django.db.models import Q
from django.conf import settings


def compute_package_declared_license_expression_spdx(apps, schema_editor):
    """
    Compute DiscoveredPackage `declared_license_expression_spdx`, when missing,
    from `declared_license_expression`, when available.
    """
    from licensedcode.cache import build_spdx_license_expression

    if settings.IS_TESTS:
        return

    DiscoveredPackage = apps.get_model("scanpipe", "DiscoveredPackage")
    queryset = DiscoveredPackage.objects.filter(
        ~Q(declared_license_expression="") & Q(declared_license_expression_spdx="")
    ).only("declared_license_expression")

    object_count = queryset.count()
    print(f"\nCompute declared_license_expression_spdx for {object_count:,} packages.")

    chunk_size = 2000
    iterator = queryset.iterator(chunk_size=chunk_size)

    unsaved_objects = []
    for index, package in enumerate(iterator, start=1):
        if spdx := build_spdx_license_expression(package.declared_license_expression):
            package.declared_license_expression_spdx = spdx
            unsaved_objects.append(package)

        if not (index % chunk_size) and unsaved_objects:
            print(f"  {index:,} / {object_count:,} computed")

    print("Updating DB objects...")
    DiscoveredPackage.objects.bulk_update(
        objs=unsaved_objects,
        fields=["declared_license_expression_spdx"],
        batch_size=1000,
    )


def compute_resource_detected_license_expression(apps, schema_editor):
    """
    Compute CodebaseResource `detected_license_expression` and
    `detected_license_expression_spdx` from old `license_expressions` field.
    """
    from license_expression import combine_expressions
    from licensedcode.cache import build_spdx_license_expression

    if settings.IS_TESTS:
        return

    CodebaseResource = apps.get_model("scanpipe", "CodebaseResource")
    queryset = CodebaseResource.objects.filter(~Q(license_expressions=[])).only(
        "license_expressions"
    )

    object_count = queryset.count()
    print(f"\nCompute detected_license_expression for {object_count:,} resources.")

    chunk_size = 2000
    iterator = queryset.iterator(chunk_size=chunk_size)

    unsaved_objects = []
    for index, resource in enumerate(iterator, start=1):
        combined_expression = str(combine_expressions(resource.license_expressions))
        # gpl-2.0 OR broadcom-linking-unmodified OR proprietary-license
        # build_spdx_license_expression("broadcom-linking-unmodified")
        # AttributeError: 'LicenseSymbol' object has no attribute 'wrapped'
        try:
            license_expression_spdx = build_spdx_license_expression(combined_expression)
        except AttributeError as error:
            resource.project.add_error(
                error=error,
                model=resource.__class__,
                details={"combined_expression": combined_expression}
            )
            continue

        resource.detected_license_expression = combined_expression
        resource.detected_license_expression_spdx = license_expression_spdx
        unsaved_objects.append(resource)

        if not (index % chunk_size) and unsaved_objects:
            print(f"  {index:,} / {object_count:,} computed")

    print("Updating DB objects...")
    CodebaseResource.objects.bulk_update(
        objs=unsaved_objects,
        fields=[
            "detected_license_expression",
            "detected_license_expression_spdx",
        ],
        batch_size=1000,
    )


def _convert_matches_to_detections(license_matches):
    """
    Return a list of scancode v32 LicenseDetection mappings from provided
    ``license_matches``: a list of the scancode v31 LicenseMatch mappings.
    """
    from license_expression import combine_expressions
    from licensedcode.detection import get_uuid_on_content
    from commoncode.text import python_safe_name

    match_attributes = ["score", "start_line", "end_line", "matched_text"]
    rule_attributes = [
        "matched_length",
        "match_coverage",
        "matcher",
        "rule_relevance",
    ]
    license_detection = {}
    detection_matches = []

    for match in license_matches:
        detection_match = {}

        for attribute in match_attributes:
            detection_match[attribute] = match[attribute]
        for attribute in rule_attributes:
            detection_match[attribute] = match["matched_rule"][attribute]

        detection_match["rule_identifier"] = match["matched_rule"]["identifier"]
        detection_match["license_expression"] = match["matched_rule"][
            "license_expression"
        ]
        detection_match["rule_url"] = None
        detection_matches.append(detection_match)

    license_expressions = [match["license_expression"] for match in detection_matches]
    hashable_details = tuple(
        [
            (match["score"], match["rule_identifier"], match["matched_text"])
            for match in detection_matches
        ]
    )
    uuid = get_uuid_on_content(hashable_details)

    license_detection["matches"] = detection_matches
    license_detection["license_expression"] = str(
        combine_expressions(license_expressions)
    )
    license_detection["identifier"] = "{}-{}".format(
        python_safe_name(license_detection["license_expression"]), uuid
    )

    return [license_detection]


def compute_resource_license_detections(apps, schema_editor):
    """Compute CodebaseResource `license_detections` from old `licenses` field."""
    if settings.IS_TESTS:
        return

    CodebaseResource = apps.get_model("scanpipe", "CodebaseResource")
    queryset = CodebaseResource.objects.filter(~Q(licenses=[])).only("licenses")

    object_count = queryset.count()
    print(f"\nCompute license_detections for {object_count:,} resources.")

    chunk_size = 2000
    iterator = queryset.iterator(chunk_size=chunk_size)

    unsaved_objects = []
    for index, resource in enumerate(iterator, start=1):
        detections = _convert_matches_to_detections(resource.licenses)
        resource.license_detections = detections
        unsaved_objects.append(resource)

        if not (index % chunk_size):
            print(f"  {index:,} / {object_count:,} computed")

    print("Updating DB objects...")
    # Keeping the batch_size small as the `license_detections` content is often large,
    # and it may raise `django.db.utils.OperationalError: out of memory`
    CodebaseResource.objects.bulk_update(
        objs=unsaved_objects,
        fields=["license_detections"],
        batch_size=50,
    )


class Migration(migrations.Migration):
    dependencies = [
        ("scanpipe", "0030_scancode_toolkit_v32_model_updates"),
    ]

    operations = [
        migrations.RunPython(
            compute_package_declared_license_expression_spdx,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunPython(
            compute_resource_detected_license_expression,
            reverse_code=migrations.RunPython.noop,
        ),
        migrations.RunPython(
            compute_resource_license_detections,
            reverse_code=migrations.RunPython.noop,
        ),
    ]
