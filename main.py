import argparse
import boto3
import logging
import json
import os
import sys
import urllib.parse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description='Analyzes IAM roles in AWS to identify potential privilege escalation paths.')
    parser.add_argument('--role-name', help='The name of the IAM role to analyze.')
    parser.add_argument('--profile', help='AWS CLI profile to use for authentication.')
    parser.add_argument('--region', help='AWS region to use. Defaults to configured region or us-east-1.')
    parser.add_argument('--output-file', help='The file to write the analysis results to (JSON format).')
    return parser

def get_role_policies(iam_client, role_name):
    """
    Retrieves inline and attached managed policies for a given IAM role.

    Args:
        iam_client: Boto3 IAM client.
        role_name (str): The name of the IAM role.

    Returns:
        tuple: A tuple containing lists of inline policies and attached managed policies.
    """
    inline_policies = []
    attached_policies = []

    try:
        # Confirm the role exists. A failed lookup must not be reported
        # as a role with no policies, so any error here is re-raised
        # and main turns it into exit 1.
        iam_client.get_role(RoleName=role_name)

        # Get inline policies: list the names, fetch each document,
        # and URL decode it. get_role does not return policy documents,
        # and its RolePolicyList field holds names only.
        marker = None
        while True:
            kwargs = {'RoleName': role_name}
            if marker:
                kwargs['Marker'] = marker
            response = iam_client.list_role_policies(**kwargs)
            for policy_name in response.get('PolicyNames', []):
                doc_response = iam_client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name)
                document = doc_response.get('PolicyDocument', '')
                if isinstance(document, dict):
                    document = json.dumps(document)
                else:
                    document = urllib.parse.unquote_plus(document)
                inline_policies.append({
                    'PolicyName': policy_name,
                    'PolicyDocument': document,
                })
            if response.get('IsTruncated'):
                marker = response.get('Marker')
            else:
                break

        # Get attached managed policies
        paginator = iam_client.get_paginator('list_attached_role_policies')
        for page in paginator.paginate(RoleName=role_name):
            attached_policies.extend(page['AttachedPolicies'])

        return inline_policies, attached_policies

    except Exception as e:
        logging.error(f"Error retrieving policies for role {role_name}: {e}")
        raise

def analyze_policies(inline_policies, attached_policies, iam_client):
    """
    Analyzes the given policies for potential privilege escalation paths.

    Args:
        inline_policies (list): A list of inline policies.
        attached_policies (list): A list of attached managed policies.
        iam_client: Boto3 IAM client

    Returns:
        dict: A dictionary containing the analysis results.
    """
    analysis_results = {
        'inline_policies': [],
        'attached_policies': []
    }

    # Analyze inline policies
    for policy in inline_policies:
        policy_name = policy['PolicyName']
        try:
            policy_document = json.loads(policy['PolicyDocument'])
            analysis_results['inline_policies'].append({
                'policy_name': policy_name,
                'potentially_risky_statements': analyze_policy_document(policy_document)
            })
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding inline policy {policy_name}: {e}")
            analysis_results['inline_policies'].append({
                'policy_name': policy_name,
                'error': f"Failed to decode policy document: {e}"
            })

    # Analyze attached policies
    for policy in attached_policies:
        policy_arn = policy['PolicyArn']
        policy_name = policy['PolicyName']
        try:
            # Get policy document
            response = iam_client.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=iam_client.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            )
            policy_document = response['PolicyVersion']['Document']
            analysis_results['attached_policies'].append({
                'policy_name': policy_name,
                'policy_arn': policy_arn,
                'potentially_risky_statements': analyze_policy_document(policy_document)
            })
        except Exception as e:
            logging.error(f"Error retrieving or analyzing attached policy {policy_name} ({policy_arn}): {e}")
            analysis_results['attached_policies'].append({
                'policy_name': policy_name,
                'policy_arn': policy_arn,
                'error': f"Failed to retrieve or analyze policy document: {e}"
            })

    return analysis_results

# The CLI description promises privilege escalation paths; what
# exists in the function below is three smell tests. The grants
# escalation actually runs through, PassRole, creating policy
# versions, attaching policies, are ordinary action strings to it
# and none of them is looked for, so a clean result means none of
# the three smells, not no escalation path.
def analyze_policy_document(policy_document):
    """
    Analyzes a single policy document for potentially risky statements.

    Args:
        policy_document (dict): The policy document to analyze.

    Returns:
        list: A list of potentially risky statements.
    """
    risky_statements = []
    statements = policy_document.get('Statement', [])
    # A policy with a single statement sometimes writes it as one object
    # instead of a one item list; treat both shapes the same.
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if isinstance(statement, str):
             logging.warning("Invalid statement format. It should be a dict.  Ignoring this statement.")
             continue

        effect = statement.get('Effect', '').lower()
        # Conditions are never read: an Allow narrowed to one source
        # address or one hour still flags exactly like an unconditional
        # one, and NotAction statements, whose meaning inverts, are
        # read here as if the listed actions were the granted ones.
        if effect == 'allow':
            # Action and Resource each come as a single string or as a
            # list. Normalise both to a set of strings first. The old
            # code compared 'sts:AssumeRole' against a list it had just
            # lowercased, so the comparison could never match, and the
            # single string form was never checked at all.
            actions = statement.get('Action') or []
            if isinstance(actions, str):
                actions = [actions]
            action_set = {a.lower() for a in actions if isinstance(a, str)}
            resources = statement.get('Resource') or []
            if isinstance(resources, str):
                resources = [resources]

            # The elif chain gives a statement at most one reason: a
            # wildcard action hides a wildcard resource and an
            # AssumeRole grant sitting in the same statement. And both
            # wildcard tests are exact equality, so the service shaped
            # wildcards that carry most real overreach, s3:* or iam:*,
            # and resource suffixes like a bucket ARN ending in /*,
            # match nothing here and pass as unremarkable.
            if '*' in action_set:
                risky_statements.append({
                    'statement': statement,
                    'reason': 'Wildcard action'
                })
            elif '*' in resources:
                risky_statements.append({
                    'statement': statement,
                    'reason': 'Wildcard resource'
                })
            elif 'sts:assumerole' in action_set:
                risky_statements.append({
                    'statement': statement,
                    'reason': 'sts:AssumeRole permission found.'
                })

    return risky_statements

def validate_role_name(role_name):
     """
     Validates that the role name is a non-empty string.
     Args:
         role_name: The role name to validate.
     Raises:
         ValueError: If the role name is invalid.
     """
     if not isinstance(role_name, str) or not role_name:
         raise ValueError("Role name must be a non-empty string.")


def main():
    """
    Main function to execute the IAM Role Analyzer.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Without a role name there is nothing to analyze, but the old code
    # carried on and called AWS with a None role name, then printed an
    # empty result and exited 0. That is a usage error, so say so here.
    if not args.role_name:
        parser.error("--role-name is required")
    try:
        validate_role_name(args.role_name)
    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        sys.exit(1)

    profile_name = args.profile
    region_name = args.region or os.environ.get('AWS_REGION') or 'us-east-1'  # Default region

    try:
        # Use AWS CLI profile if provided
        if profile_name:
            session = boto3.Session(profile_name=profile_name, region_name=region_name)
            iam_client = session.client('iam')
        else:
            iam_client = boto3.client('iam', region_name=region_name)

        role_name = args.role_name

        # Get role policies
        inline_policies, attached_policies = get_role_policies(iam_client, role_name)

        # Analyze policies
        analysis_results = analyze_policies(inline_policies, attached_policies, iam_client)

        # Output results to file if specified
        if args.output_file:
            try:
                with open(args.output_file, 'w') as f:
                    json.dump(analysis_results, f, indent=4)
                logging.info(f"Analysis results written to {args.output_file}")
            except Exception as e:
                logging.error(f"Error writing results to file: {e}")
                sys.exit(1)
        else:
            # Print results to console
            print(json.dumps(analysis_results, indent=4))

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Example usage (from the command line):
    # python cma_iam_role_analyzer.py --role-name MyRole --profile MyProfile --output-file analysis.json
    # python cma_iam_role_analyzer.py --role-name MyRole
    # python cma_iam_role_analyzer.py --role-name MyRole --region us-west-2

    main()