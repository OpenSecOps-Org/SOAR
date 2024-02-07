# Importing necessary libraries
import os
import boto3
import json


# Get the ARN template
ARN_TEMPLATE = os.environ['ARN_TEMPLATE']

# Creating a client object for AWS Lambda
client = boto3.client('lambda')


# Defining the lambda_handler function
def lambda_handler(finding, _context):
    # Printing the input finding
    print(finding)

    # Extracting the region from the input finding
    region = finding['Resources'][0]['Region']

    # Insert it into the ARN template
    fn_arn = ARN_TEMPLATE.replace('<REGION>', region)

    print(f"Invoking lambda with ARN {fn_arn}...")

    # Invoking the Lambda function with the modified ARN and input finding
    response = client.invoke(FunctionName=fn_arn,
                             InvocationType='RequestResponse',
                             Payload=json.dumps(finding)
                             )

    # Printing the response from the invoked Lambda function
    print(response)

    # Returning True to indicate successful execution
    return True
