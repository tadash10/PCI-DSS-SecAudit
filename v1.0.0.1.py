import boto3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, filename='ec2_compliance_check.log', 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Configurable parameters
SSH_CIDR_RANGE = '0.0.0.0/0'
OUTDATED_AMIS = ['ami-0123456789abcdef0']  # Example outdated AMI IDs

def check_ec2_instances():
    """Check EC2 instances for PCI DSS compliance."""
    ec2 = boto3.client('ec2')

    try:
        # Describe all EC2 instances
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

    # Check instances for compliance
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            public_ip = instance.get('PublicIpAddress')
            ami_id = instance['ImageId']

            # Check security groups for issues
            security_group_issues = check_security_groups(security_groups, instance['SecurityGroups'])

            # Check public accessibility
            if public_ip:
                logging.warning("Instance %s is publicly accessible via IP %s.", instance_id, public_ip)

            # Check AMI for security updates
            if not check_ami_security(ami_id):
                logging.warning("Instance %s is using an outdated or insecure AMI: %s.", instance_id, ami_id)

            # Output issues
            if security_group_issues:
                logging.info("Issues found for instance %s:", instance_id)
                for issue in security_group_issues:
                    logging.info("  - %s", issue)

def check_security_groups(security_groups, instance_sgs):
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
                        if ip_range['CidrIp'] == SSH_CIDR_RANGE:
                            issues.append(f"Security group {sg_id} allows SSH access from {SSH_CIDR_RANGE}.")
    
    return issues

def check_ami_security(ami_id):
    """Check if the AMI is outdated or insecure."""
    return ami_id not in OUTDATED_AMIS  # Replace with a more robust check if needed

if __name__ == "__main__":
    check_ec2_instances()
