import boto3
import botocore
# import jsonschema
import json
import traceback

from extutil import remove_none_attributes, account_context, ExtensionHandler, \
    ext, component_safe_name

eh = ExtensionHandler()

def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        region = account_context(context)['region']
        eh.capture_event(event)
        prev_state = event.get("prev_state")
        cdef = event.get("component_def")
        cname = event.get("component_name")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        document = cdef.get("document")
        policy_hash = json.dumps(document, sort_keys=True)
        policy_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname)
        path = "/kloudcommand/" #Not sure how well this is supported, probably poorly
        policy_arn = gen_iam_policy_arn(policy_name, account_number, path)
        pass_back_data = event.get("pass_back_data", {})
        description = cdef.get("description") or "This policy was created by CloudKommand"
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            if not prev_state:
                eh.add_op("create_policy")
            else:
                eh.add_op("get_policy")

        elif event.get("op") == "delete":
            eh.add_op("remove_policy", {"arn":prev_state.get("props").get("arn"), "complete": True})
        
        get_policy(prev_state, policy_name, policy_hash)
        remove_policy()
        create_policy(policy_name, description, path, policy_hash, account_number)
        create_policy_version(policy_arn, policy_name, policy_hash)
            
        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="create_policy_version")
def create_policy_version(policy_arn, policy_name, policy_hash):
    iam_client = boto3.client("iam")

    try:
        policy_response = iam_client.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=policy_hash,
            SetAsDefault=True
        )
        eh.add_log("Created New Policy Version", policy_response)
    except botocore.exceptions.ClientError as e:
        eh.add_log("Error in Creating Policy Version", {"error": str(e)}, is_error=True)
        if e.response['Error']['Code'] == 'MalformedPolicyDocument':
            eh.declare_return(200, 0, error_code=str(e), error_details={"policy": policy_hash}, callback=False)
            return 0
        else:
            raise e

    try:
        response = iam_client.list_policy_versions(
            PolicyArn=policy_arn,
            MaxItems=10
        )
        existing_versions = response['Versions']
        for version in existing_versions:
            if not version.get("IsDefaultVersion"):
                response = iam_client.delete_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version.get("VersionId")
                )
                eh.add_log("Deleting Old Policy Version", response)
            
    except Exception as e:
        eh.add_log("Error in Deleting Old Policy Versions", {"error": str(e)}, is_error=True)

    props={
        "arn": policy_arn,
        "name": policy_name,
        "policy_hash": policy_hash
    }

    links = {
        "Policy": gen_iam_policy_link(policy_arn)
    }

    eh.complete_op("create_policy_version")
    eh.declare_return(200, 100, success=True, props=props, links=links)


@ext(handler=eh, op="create_policy")
def create_policy(policy_name, description, path, policy_hash, account_number):

    iam_client = boto3.client("iam")
    try:
        result = iam_client.create_policy(**remove_none_attributes({
            "PolicyName": policy_name,
            "Description": description,
            "Path": path,
            "PolicyDocument": policy_hash
        }))

        eh.add_log("Created Policy", result)

        props={
            "arn": result["Policy"]["Arn"],
            "name": policy_name,
            "policy_hash": policy_hash
        }

        links = {
            "Policy": gen_iam_policy_link(result["Policy"]["Arn"])
        }

        eh.declare_return(200, 100, success=True, props=props, links=links)
    
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            eh.add_log("Policy Already Exists")
            eh.add_op("create_policy_version")
        elif e.response['Error']['Code'] == 'MalformedPolicyDocument':
            eh.add_log("Error in Creating Policy Version", {"error": str(e)}, is_error=True)
            eh.declare_return(200, 0, error_code=str(e), error_details={"policy": policy_hash}, callback=False)
            return 0
        else:
            eh.add_log("Error in Creating Policy Version", {"error": str(e)}, is_error=True)
            raise e

    eh.complete_op("create_policy")

@ext(handler=eh, op="get_policy")
def get_policy(prev_state, policy_name, policy_hash):
    try:
        old_policy_arn = prev_state["props"]["arn"]
        old_policy_name = prev_state["props"]["name"]
        # old_policy_hash = prev_state["props"]["policy_hash"]
    except:
        prev_state = None
        old_policy_arn = None
        old_policy_name = None
        # old_policy_hash = None

    iam_client = boto3.client("iam")
    if old_policy_arn:
        try:
            policy_response = iam_client.get_policy(PolicyArn=old_policy_arn)
            eh.add_log("Got Existing Policy", policy_response)
            if policy_name != old_policy_name:
                eh.add_op("remove_old", {"arn": old_policy_arn, "complete": False})
                eh.add_op("create_policy")
            else:
                eh.add_op("create_policy_version")

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                eh.add_op("create_policy")
            else:
                eh.add_log("Get Policy Failed", e.response, is_error=True)
                eh.declare_return(200, 0, error_message="get_policy_failed", callback_sec=4)
    else:
        eh.add_op("create_policy")

    eh.complete_op("get_policy")

#This may be different with "paths"
def gen_iam_policy_arn(policy_name, account_number, path="/"):
    #arn:aws:iam::227993477930:policy/3aba481ac88bcbc5d94567e9f93339a7-iam
    return f"arn:aws:iam::{account_number}:policy{path}{policy_name}"

#I bet this is different with "paths"
def gen_iam_policy_link(policy_arn):
    return f"https://console.aws.amazon.com/iam/home?region=us-east-1#/policies/{policy_arn}$serviceLevelSummary"

@ext(handler=eh, op="remove_policy")
def remove_policy():
    op_info = eh.ops['remove_policy']
    policy_arn = op_info['arn']
    complete = op_info['complete']

    iam_client = boto3.client("iam")
    try:
        iam_client.get_policy(
            PolicyArn = policy_arn
        )

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntityException':
            eh.add_log("Old Policy Doesn't Exist", {"policy_arn": policy_arn})
            eh.complete_op("remove_policy")
            if complete:
                eh.declare_return(200, 100, success=True)
            return None
        else:
            raise e

    policy_groups, policy_users, policy_roles = get_all_entities_for_policy(policy_arn)

    for group in policy_groups:
        try:
            response = iam_client.detach_group_policy(
                GroupName = group.get("GroupName"),
                PolicyArn = policy_arn
            )
            eh.add_log("Detaching From Group", response)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntityException':
                pass
            else:
                raise e

    for user in policy_users:
        try:
            response = iam_client.detach_user_policy(
                UserName = user.get("UserName"),
                PolicyArn = policy_arn
            )
            eh.add_log("Detaching From User", response)
        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntityException':
                pass
            else:
                raise e

    for role in policy_roles:
        try:
            response = iam_client.detach_role_policy(
                RoleName = role.get("RoleName"),
                PolicyArn = policy_arn
            )
            eh.add_log("Detaching From Role", response)

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntityException':
                pass
            # elif e.response['Error']['Code'] == 'ServiceFailureException':
            #     return "something that says call me again"
            else:
                raise e

    response = iam_client.list_policy_versions(
        PolicyArn = policy_arn,
        MaxItems = 10
    )

    versions = response.get("Versions")

    if versions:
        for version in versions:
            if not version.get("IsDefaultVersion"):
                iam_client.delete_policy_version(
                    PolicyArn = policy_arn,
                    VersionId = version['VersionId']
                )

    response = iam_client.delete_policy(
        PolicyArn = policy_arn
    )

    eh.add_log("Deleted Policy", response)

    eh.complete_op("remove_policy")
    if complete:
        eh.declare_return(200, 100, success=True)

def get_all_entities_for_policy(policy_arn):
    iam_client = boto3.client("iam")

    marker = 'marker'
    policy_groups = []
    policy_users = []
    policy_roles = []
    while marker:
        params = remove_none_attributes({
            "PolicyArn": policy_arn,
            "MaxItems": 100,
            "Marker": marker if marker != "marker" else None
        })

        response = iam_client.list_entities_for_policy(**params)

        policy_groups.extend(response.get("PolicyGroups", []))
        policy_users.extend(response.get("PolicyUsers", []))
        policy_roles.extend(response.get("PolicyRoles", []))

        marker = response.get("Marker")

    return policy_groups, policy_users, policy_roles

    
