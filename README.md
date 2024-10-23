# PCI-DSS-SecAudit
This script checks AWS EC2 instances for compliance with PCI DSS standards. It performs a series of checks, including security group configurations, AMI security status, patching levels, access controls, and AWS CloudTrail logging.
Features

    Security Group Checks: Identifies overly permissive security groups that allow all inbound traffic or SSH access from any IP address.
    AMI Security Check: Validates if instances are using outdated or insecure AMIs.
    Patching Status: Integrates with AWS Systems Manager (SSM) to verify if instances are up-to-date with patches.
    Access Control Assessment: Checks IAM roles and policies to ensure they follow the principle of least privilege.
    CloudTrail Verification: Ensures that AWS CloudTrail is enabled to capture API calls for auditing.

Requirements

    Python 3.x
    Boto3 library: Install via pip if not already installed:

    bash

    pip install boto3

Configuration

The script allows configurable parameters via command-line arguments:

    --ssh_cidr: CIDR range for SSH access (default: 0.0.0.0/0)
    --outdated_amis: List of outdated AMI IDs to check against (default: ['ami-0123456789abcdef0'])

Usage

Run the script from the command line:

bash

python ec2_compliance_checker.py --ssh_cidr <your_ssh_cidr> --outdated_amis <ami_id1> <ami_id2> ...

Example

bash

python ec2_compliance_checker.py --ssh_cidr 192.168.1.0/24 --outdated_amis ami-0123456789abcdef0 ami-abcdef0123456789

Output

The script generates a compliance report in JSON format, saved as compliance_report.json, and logs detailed information in ec2_compliance_check.log.
Logging

Logs are generated for compliance checks, including warnings for compliance issues and errors encountered during execution. Check ec2_compliance_check.log for more details.
Testing

The script includes unit tests that can be run to ensure the accuracy and reliability of its functions. To run the tests, execute:

bash

python -m unittest test_compliance_checks.py

Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.
License

This project is licensed under the MIT License - see the LICENSE file for details.
