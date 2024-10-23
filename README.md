# PCI-DSS-SecAudit
 Python script that uses the boto3 library to check if Amazon EC2 instances meet specific PCI DSS standards. This script will check for the following common PCI DSS requirements:

    Ensure that EC2 instances have security groups that restrict inbound traffic.
    Ensure that all instances are not publicly accessible unless necessary.
    Ensure that instances are using updated and secure AMIs.

Before running the script, make sure you have the necessary AWS credentials set up and the boto3 library installed. You can install it via pip if you haven't done so:

bash

pip install boto3
