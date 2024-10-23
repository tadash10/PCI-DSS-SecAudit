import boto3
import logging
import json
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, filename='ec2_compliance_check.log', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configurable parameters
SSH_CIDR_RANGE = '0.0.0.0/0'  # Default; can be overridden by command-line argument
OUTDATED_AMIS = ['ami-0123456789abcdef0']  # Example outdated AMI IDs

def parse_arguments():
    """Parse command-line arguments for configuration."""
    parser = argparse.ArgumentParser(description='Check EC2 instances for PCI DSS compliance.')
    parser.add_argument('--ssh_cidr', type=str, default=SSH_CIDR_RANGE, help='CIDR range for SSH access')
    parser.add_argument('--outdated_amis', type=str, nargs='*', default=OUTDATED_AMIS,
                        help='List of outdated AMI IDs to check against')
    return parser.parse_args()

def check_ec2_instances(ssh_cidr_range, outdated_amis):
    """Check EC2 instances for PCI DSS compliance."""
    ec2 = boto3.client('ec2')

    try:
        instances = ec2.describe_instances()
    except Exception as e:
        logging.error("Failed to retrieve EC2 instances: %s", e)
        return

    # Collect security groups
    security_groups = {}
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            for sg in instance['SecurityGroups']:
                sg_id = sg['GroupId']
                if sg_id not in security_groups:
                    try:
                        sg_desc = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
                        security_groups[sg_id] = sg_desc
                    except Exception as e:
                        logging.error("Failed to describe security group %s: %s", sg_id, e)

    compliance_report = []

    # Check instances for compliance
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            public_ip = instance.get('PublicIpAddress')
            ami_id = instance['ImageId']

            # Check security groups for issues
            security_group_issues = check_security_groups(security_groups, instance['SecurityGroups'], ssh_cidr_range)

            # Check public accessibility
            if public_ip:
                logging.warning("Instance %s is publicly accessible via IP %s.", instance_id, public_ip)

            # Check AMI for security updates
            if not check_ami_security(ami_id, outdated_amis):
                logging.warning("Instance %s is using an outdated or insecure AMI: %s.", instance_id, ami_id)

            # Compile issues into report
            compliance_report.append({
                'instance_id': instance_id,
                'security_group_issues': security_group_issues,
                'public_ip': public_ip,
                'outdated_ami': ami_id if ami_id in outdated_amis else None
            })

    # Output the compliance report
    output_report(compliance_report)

def check_security_groups(security_groups, instance_sgs, ssh_cidr_range):
    """Check the security groups associated with an instance for compliance issues."""
    issues = []
    
    for sg in instance_sgs:
        sg_id = sg['GroupId']
        sg_desc = security_groups[sg_id]

        # Consolidated check for inbound rules
        for permission in sg_desc['IpPermissions']:
            if permission['IpProtocol'] == '-1':  # All traffic
                issues.append(f"Security group {sg_id} allows all inbound traffic.")
            if permission['IpProtocol'] == 'tcp' and 'FromPort' in permission and permission['FromPort'] == 22:
                if permission['IpRanges']:
                    for ip_range in permission['IpRanges']:
                        if ip_range['CidrIp'] == ssh_cidr_range:
                            issues.append(f"Security group {sg_id} allows SSH access from {ssh_cidr_range}.")
    
    return issues

def check_ami_security(ami_id, outdated_amis):
    """Check if the AMI is outdated or insecure."""
    return ami_id not in outdated_amis  # Replace with a more robust check if needed

def output_report(report):
    """Output the compliance report in JSON format."""
    with open('compliance_report.json', 'w') as report_file:
        json.dump(report, report_file, indent=4)
    logging.info("Compliance report generated: compliance_report.json")

if __name__ == "__main__":
    args = parse_arguments()
    check_ec2_instances(args.ssh_cidr, args.outdated_amis)
