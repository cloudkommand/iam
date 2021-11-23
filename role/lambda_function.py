import boto3
import botocore
# import jsonschema
import json
import traceback

from extutil import remove_none_attributes, account_context, ExtensionHandler, \
    ext, component_safe_name

# def validate_state(state):
# "prev_state": prev_state,
# "component_def": component_def, RENDERED
# "op": op,
# "s3_object_name": object_name,
# "pass_back_data": pass_back_data
#     jsonschema.validate()
eh = ExtensionHandler()

def lambda_handler(event, context):
    try:
        print(f"event = {event}")
        account_number = account_context(context)['number']
        eh.capture_event(event)

        prev_state = event.get("prev_state")
        cdef = event.get("component_def")
        cname = event.get("component_name")
        project_code = event.get("project_code")
        repo_id = event.get("repo_id")
        description = cdef.get("description") or f"Role for component {cname}"
        max_session_duration_seconds = cdef.get("max_session_duration_seconds") or 3600
        policies = cdef.get("policies") or []
        policy_arns = cdef.get("policy_arns") or []
        role_name = cdef.get("name") or component_safe_name(project_code, repo_id, cname)
        basic_lambda_policy = set(["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]) if cdef.get("include_basic_lambda_policy", True) else set()
        desired_policy_arns = list(set(policy_arns) | set(map(lambda x: x['arn'], policies)) | basic_lambda_policy)
        print(f"desired_policy_arns = {desired_policy_arns}")
        role_services = cdef.get("role_services") or ["lambda"]
        
        tags = cdef.get("tags") or {}
        pass_back_data = event.get("pass_back_data", {})
        if pass_back_data:
            pass
        elif event.get("op") == "upsert":
            eh.add_op("get_role")

        elif event.get("op") == "delete":
            eh.add_op("remove_old", {"name":role_name})

        get_role(prev_state, role_name, role_services, desired_policy_arns, description, max_session_duration_seconds, tags)
        create_role(role_name, description, tags, role_services, cname, account_number)
        update_role(role_name, description, max_session_duration_seconds)
        remove_tags(role_name)
        add_tags(role_name, tags)
        add_policy_arns(role_name)
        remove_policy_arns(role_name)
        update_assume_role_policy(role_name, role_services)
        remove_role()

        return eh.finish()

    except Exception as e:
        msg = traceback.format_exc()
        print(msg)
        eh.add_log("Uncovered Error", {"error": msg}, is_error=True)
        eh.declare_return(200, 0, error_code=str(e))
        return eh.finish()

@ext(handler=eh, op="get_role")
def get_role(prev_state, role_name, role_services, desired_policy_arns, description, max_session_duration_seconds, desired_tags):
    # create_and_remove = False
    add_arns = []
    remove_policy_arns = []
    try:
        old_role_name = prev_state["props"]["name"]
        if old_role_name != role_name:
            # create_and_remove = True
            eh.add_op("remove_old", {"name": old_role_name, "create_and_remove": True})
            eh.add_op("create_role")
            eh.add_op("add_policy_arns", desired_policy_arns)
            return None
    except:
        pass

    iam_client = boto3.client("iam")

    try:
        role_response = iam_client.get_role(RoleName=role_name).get("Role")
        eh.add_log("Got Existing Role", role_response)
        eh.add_props({
            "arn": role_response['Arn'],
            "name": role_response['RoleName'],
            "role_id": role_response['RoleId']
        })
        eh.add_links({"Role": gen_iam_role_link(role_name)})

        old_description = role_response['Description']
        old_msds = role_response['MaxSessionDuration']
        if ((description != old_description) or (max_session_duration_seconds != old_msds)):
            eh.add_op("update_role")
            
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            eh.add_log("Role Does Not Exist", {"error": str(e)})
            eh.add_op("create_role")
            eh.add_op("add_policy_arns", desired_policy_arns)
            return None
        else:
            eh.add_log("Get Role Failed", {"error": str(e)}, True)
            eh.retry_error(str(e))
            return None

    try:
        response = iam_client.list_attached_role_policies(
            RoleName=role_name,
            MaxItems=10
        )
        attached_policy_arns = list(map(lambda x: x['PolicyArn'], response.get("AttachedPolicies")))
        eh.add_log("Got Role Policies", response)
        add_arns = list(set(desired_policy_arns)-set(attached_policy_arns))
        remove_policy_arns = list(set(attached_policy_arns)-set(desired_policy_arns))
        if add_arns:
            eh.add_op("add_policy_arns", add_arns)
        if remove_policy_arns:
            eh.add_op("remove_policy_arns", remove_policy_arns)

    except botocore.exceptions.ClientError as e:
        eh.add_log("Get Role Policies Failed", str(e), True)
        eh.retry_error(str(e))
        return None

    try:
        tags = {}
        first = True
        cursor = None
        while first or cursor:
            first = False
            params = remove_none_attributes({
                "RoleName": role_name,
                "Marker": cursor
            })
            response = iam_client.list_role_tags(**params)
            print(f"tags_response = {response}")
            tags.update({
                item["Key"]: item["Value"]
                for item in response.get("Tags")
            })
            if response.get("IsTruncated"):
                cursor = response.get("Marker")

        eh.add_log("Got Tags", {"tags": tags})
        if tags != desired_tags:
            eh.add_op("add_tags")
        old_keys = set(tags.keys()) - set(desired_tags.keys())
        if old_keys:
            eh.add_op("remove_tags", old_keys)

    except botocore.exceptions.ClientError as e:
        eh.add_log("Error Getting Tags", str(e), True)
        eh.retry_error(str(e))
        return None

    try:
        iam = boto3.resource('iam')
        role = iam.Role(role_name)
        existing_document = role.assume_role_policy_document
        print(f"existing_document = {existing_document}")
        desired_document = create_assume_role_policy(role_services)
        print(f"desired document = {desired_document}")
        if existing_document != desired_document:
            eh.add_op("update_role_services")

    except botocore.exceptions.ClientError as e:
        eh.add_log("Error Getting Assume Role Policy", str(e), True)
        eh.retry_error(str(e))
        return None


@ext(handler=eh, op="remove_old")
def remove_role():
    iam_client = boto3.client("iam")
    role_name = eh.ops['remove_old'].get("name")
    car = eh.ops['remove_old'].get("create_and_remove")
    list_response = {}
    
    try:
        list_response = iam_client.list_attached_role_policies(
            RoleName=role_name
        )
        print(f"list_response = {list_response}")

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ['NoSuchEntityException', 'NoSuchEntity']:
            eh.add_log(f"Role Does Not Exist", {"role_name": role_name})
            eh.complete_op("remove_old")
            return None
        else:
            eh.add_log(f"Error Listing Role Policies", {"error": str(e)}, True)
            eh.retry_error(str(e), 97 if car else 20)
            return None

    for policy in list_response.get("AttachedPolicies", []):
        try:
            response = iam_client.detach_role_policy(
                RoleName = role_name,
                PolicyArn = policy['PolicyArn']
            )
            eh.add_log(f"Detaching From Role", {"policy_arn": policy['PolicyArn']})

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntityException':
                pass
            else:
                eh.retry_error(str(e), 98 if car else 40)

    try:
        role_response = iam_client.delete_role(
            RoleName = role_name
        )
        eh.add_log("Deleted Role", role_response)

    except botocore.exceptions.ClientError as e:
        eh.add_log("Error Deleting Role", {"error": str(e)}, is_error=True)
        eh.retry_error(str(e), 99 if car else 60)


@ext(handler=eh, op="add_policy_arns")
def add_policy_arns(role_name):
    iam_client = boto3.client("iam")
    add_policy_arns = eh.ops['add_policy_arns']
    iter_add_policy_arns = list(add_policy_arns)

    for add_policy_arn in iter_add_policy_arns:
        try:
            attach_response = iam_client.attach_role_policy(
                RoleName=role_name,
                PolicyArn=add_policy_arn
            )
            eh.ops['add_policy_arns'].remove(add_policy_arn)
            eh.add_log("Added Policy to Role", {"ARN": add_policy_arn, "response": attach_response})
        except botocore.exceptions.ClientError as e:
            eh.add_log("Add Policy Error", {"error": str(e)}, True)
            eh.retry_error(str(e), 60)
    

@ext(handler=eh, op="remove_policy_arns")
def remove_policy_arns(role_name):
    iam_client = boto3.client("iam")
    remove_policy_arns = eh.ops['remove_policy_arns']

    for remove_policy_arn in remove_policy_arns:
        try:
            remove_response = iam_client.detach_role_policy(
                RoleName=role_name,
                PolicyArn=remove_policy_arn
            )
            eh.ops['add_policy_arns'].remove(remove_policy_arn)
            eh.add_log("Removed Policy From Role", {"ARN": remove_policy_arn, "response": remove_response})

        except botocore.exceptions.ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                eh.ops['add_policy_arns'].remove(remove_policy_arn)
                pass
            else:
                eh.add_log("Remove Policy Error", {"error": str(e)}, True)
                eh.retry_error(str(e), 90)

@ext(handler=eh, op="update_role_services")
def update_assume_role_policy(role_name, role_services):
    iam_client = boto3.client("iam")

    assume_role_policy = create_assume_role_policy(role_services)

    try:
        policy_response = iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(assume_role_policy)
        )
        eh.add_log("Updated Assume Role Policy", policy_response)
    except botocore.exceptions.ClientError as e:
        eh.add_log("Assume Role Policy Error", {"error": str(e)}, True)
        eh.retry_error(str(e), 95)

@ext(handler=eh, op="add_tags")
def add_tags(role_name, tags):
    iam_client = boto3.client("iam")

    formatted_tags = format_tags(tags)

    try:
        response = iam_client.tag_role(
            RoleName=role_name,
            Tags=formatted_tags
        )
        eh.add_log("Tags Set", response)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] in ["LimitExceededException"]:
            eh.add_log("Tag Limit Hit", {"tags": tags, "role_name": role_name}, True)
            eh.perm_error("Tag Limit Hit", 50)
        elif e.response['Error']['Code'] in ["InvalidInputException"]:
            eh.add_log("Invalid Tags", {"tags": tags, "role_name": role_name}, True)
            eh.perm_error("Invalid Tags", 50)
        else:
            eh.add_log("Set Tags Error", {"error": str(e)}, True)
            eh.retry_error(str(e), 50)
        

@ext(handler=eh, op="remove_tags")
def remove_tags(role_name):
    iam_client = boto3.client("iam")
    remove_tags = eh.ops['remove_tags']

    try:
        response = iam_client.untag_role(
            RoleName=role_name,
            TagKeys=remove_tags
        )
        eh.add_log("Tags Removed", {"tags_removed": remove_tags})

    except botocore.exceptions.ClientError as e:
        eh.add_log("Set Tags Error", {"error": str(e)}, True)
        eh.retry_error(str(e), 40)
        

@ext(handler=eh, op="create_role")
def create_role(role_name, description, tags, role_services, component_name, account_number):
    iam_client = boto3.client("iam")
    assume_role_policy = create_assume_role_policy(role_services)

    try:
        role_params = remove_none_attributes({
            "Path": "/cloudkommand/",
            "RoleName": role_name,
            "AssumeRolePolicyDocument": json.dumps(assume_role_policy),
            "Description": description or f"CK role for component {component_name}",
            "Tags": format_tags(tags) or None
        })

        role_response = iam_client.create_role(**role_params).get("Role")
        eh.add_props({
            "arn": role_response['Arn'],
            "name": role_response['RoleName'],
            "role_id": role_response['RoleId']
            # "role_services": assume_role_policy.get("Statement")[0]
            })
        eh.add_links({"Role": gen_iam_role_link(role_name)})
        eh.add_log("Created New Role", role_response)

    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            pass
        elif e.response['Error']['Code'] == 'LimitExceeded':
            eh.add_log("Role Limit Exceeded", {"error": str(e)}, True)
            eh.perm_error(str(e), 0)
        else:
            eh.add_log("Create Role Error", {"error": str(e)}, True)
            eh.retry_error(str(e), 15)
    

@ext(handler=eh, op="update_role")
def update_role(role_name, description, max_session_duration_seconds):
    iam_client = boto3.client("iam")

    try:
        response = iam_client.update_role(
            RoleName=role_name,
            Description=description,
            MaxSessionDuration=max_session_duration_seconds
        )
        eh.add_log("Updated Role", response)
    
        # add_arns = list(set(desired_policy_arns)-set(attached_policy_arns)) or None
        # remove_policy_arns = list(set(attached_policy_arns)-set(desired_policy_arns)) or None

    except botocore.exceptions.ClientError as e:
        eh.add_log("Update Role Failed", str(e), True)
        eh.retry_error(str(e), 30)

def gen_role_props(role_name, account_number, role_services, policy_arns, path):
    return {
        "name": role_name,
        "arn": gen_iam_role_arn(role_name, account_number, path),
        "policy_arns": policy_arns,
        "role_services": role_services
    }

def create_assume_role_policy(role_services):
    '''
        Note that this function returns the exact policy 
        CloudFormation would attach to a lambda's role
    '''
    #ldkfjd
    in_policy_services = list(map(lambda x: (x if x.endswith(".amazonaws.com") else f"{x}.amazonaws.com"), role_services))
    if len(in_policy_services) == 1:
        in_policy_services = in_policy_services[0]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
            "Effect": "Allow",
            "Principal": {
                "Service": in_policy_services
            },
            "Action": "sts:AssumeRole"
        }]}

def gen_iam_policy_arn(policy_name, account_number, path="/"):
    #arn:aws:iam::227993477930:policy/3aba481ac88bcbc5d94567e9f93339a7-iam
    return f"arn:aws:iam::{account_number}:policy{path}{policy_name}"

#This may be different with "paths"
def gen_iam_role_arn(role_name, account_number, path="/"):
    #arn:aws:iam::227993477930:policy/3aba481ac88bcbc5d94567e9f93339a7-iam
    return f"arn:aws:iam::{account_number}:role{path}{role_name}"

#I bet this is different with "paths"
def gen_iam_role_link(role_name):
    return f"https://console.aws.amazon.com/iam/home#/roles/{role_name}"

def format_tags(tags_dict):
    return [{"Key": k, "Value": v} for k,v in tags_dict.items()]
