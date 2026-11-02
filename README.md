![The Palm House in winter with no lettering: fern beds beaded with water, the walk running away under mist between palm trunks, the admission book shut on its lectern, snow held on the outside of the roof panes, and one high palm crown touching the glass](intro-banner.png)


# cma-IAM-Role-Analyzer

![The Palm House from the central walk: palms rising bay by bay into the roof curve, mist at shoulder height, and the keeper admission book open on its lectern with cma-iam-role-analyzer written at the head of the left page, a bundle of checked labels tied with the one berry red string beside it](banner.png)

![One curved rib of the Palm House roof with a snow line along its panes and one small palm crown behind the glass, over a herbarium specimen label, the heading plate](logo.png)

![Palm house scene in three depths: snow falls slowly outside the panes, fern fronds sway inside while a condensation bead runs down a glazing bar, and one vine tendril curls slowly at the foot of the nearest bed](scene.svg)

Analyzes IAM roles in AWS to identify potential privilege escalation paths. Uses boto3 with the operator's own AWS profile to run three statement checks (wildcard actions, wildcard resources, and sts:AssumeRole) over the attached managed policies and the inline policies of a single named role, and reports the risky statements found. AWS only. If a role lookup fails, the run reports the error and exits 1 instead of returning an empty result.

> **Potting bench notice: what a clean run does not prove.** A run that finds nothing means none of the three checks matched. Only Allow statements are examined, conditions are never read, and the tests are exact matches, so it does not mean that no privilege escalation path exists.

![Major separator: a vine tendril curling across the full rule in moss on fern silver](sep-heavy.svg)

## Install
`git clone https://github.com/ShadowStrikeHQ/cma-iam-role-analyzer`

> **Potting bench notice: clone line flagged.** The install line above points to ShadowStrikeHQ, not to ShadowGuard-AI. It is preserved as printed and flagged here, not quietly corrected.

![Minor separator: one centred vine tendril curl with plain rule on either side](sep-light.svg)

## Usage
`./cma-iam-role-analyzer [params]`

> **Potting bench notice: usage line flagged.** The usage line above is a placeholder. The parser in main.py requires --role-name and offers --profile, --region, and --output-file.

![Major separator: a vine tendril curling across the full rule in moss on fern silver](sep-heavy.svg)

## Parameters
- `-h`: Show help message and exit
- `--role-name`: The name of the IAM role to analyze.
- `--profile`: AWS CLI profile to use for authentication.
- `--region`: AWS region to use. Defaults to configured region or us-east-1.
- `--output-file`: No description provided

![Major separator: a vine tendril curling across the full rule in moss on fern silver](sep-heavy.svg)

## License
Copyright (c) ShadowStrikeHQ

> **Potting bench notice: copyright line flagged.** The closing line above reads Copyright (c) ShadowStrikeHQ, preserved as printed. The repository LICENSE file carries the MIT License.
