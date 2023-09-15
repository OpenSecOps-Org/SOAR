# Importing necessary libraries
import os
import boto3
import json

# Creating a client object for AWS Lambda
client = boto3.client('lambda')

# Getting the function ARN from environment variables
FUNCTION_ARN = os.environ['FUNCTION_ARN']

# Defining the lambda_handler function
def lambda_handler(finding, _context):
    # Printing the input finding
    print(finding)

    # Checking if FUNCTION_ARN is empty
    if (FUNCTION_ARN == ''):
        # Printing a message and returning True if FUNCTION_ARN is empty
        print("No function ARN supplied. Aborting as NOOP.")
        return True

    # Extracting the region from the input finding
    region = finding['Resources'][0]['Region']

    # Splitting the FUNCTION_ARN into its components
    arn_bits = FUNCTION_ARN.split(':')

    # Replacing the region component with the extracted region
    arn_bits[3] = region

    # Joining the modified components back into a string
    fn_arn = ':'.join(arn_bits)

    # Invoking the Lambda function with the modified ARN and input finding
    response = client.invoke(FunctionName=fn_arn,
                             InvocationType='RequestResponse',
                             Payload=json.dumps(finding)
                             )

    # Printing the response from the invoked Lambda function
    print(response)

    # Returning True to indicate successful execution
    return True