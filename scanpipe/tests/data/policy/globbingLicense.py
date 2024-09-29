import fnmatch


def match_license(license, policy):
    return fnmatch.fnmatch(license, policy['license_key'])

license_policies = [
    {'license_key': 'apache-*', 'label': 'Approved License', 'color_code': '#008000', 'compliance_alert': ''},
    {'license_key': 'mpl-*', 'label': 'Restricted License', 'color_code': '#ffcc33', 'compliance_alert': 'warning'},
    {'license_key': 'gpl-*', 'label': 'Prohibited License', 'color_code': '#c83025', 'compliance_alert': 'error'}
]


licenses_to_test = ['apache-2.0', 'mpl-1.1', 'gpl-3.0']

for license in licenses_to_test:
    for policy in license_policies:
        if match_license(license, policy):
            print(f"License {license} matches policy {policy['label']}")

