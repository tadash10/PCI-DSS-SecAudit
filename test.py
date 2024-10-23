import boto3

def check_ec2_instances():
    ec2 = boto3.client('ec2')

    # Describe all EC2 instances
    instances = ec2.describe_instances()

    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            instance_id = instance['InstanceId']
            security_groups = instance['SecurityGroups']
            public_ip = instance.get('PublicIpAddress')
            ami_id = instance['ImageId']

            # Check Security Groups
            security_group_issues = []
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_desc = ec2.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]

                # Check for inbound rules
                for permission in sg_desc['IpPermissions']:
                    if permission['IpProtocol'] == '-1':  # all traffic
                        security_group_issues.append(f"Security group {sg_id} allows all inbound traffic.")
                    if 'FromPort' in permission and permission['FromPort'] == 22:
                        if permission['IpRanges']:
                            for ip_range in permission['IpRanges']:
                                if ip_range['CidrIp'] == '0.0.0.0/0':
                                    security_group_issues.append(f"Security group {sg_id} allows SSH access from anywhere.")

            # Check public accessibility
            if public_ip:
                print(f"Instance {instance_id} is publicly accessible via IP {public_ip}.")
            
            # Check AMI for security updates
            if not check_ami_security(ami_id):
                print(f"Instance {instance_id} is using an outdated or insecure AMI: {ami_id}.")

            # Output issues
            if security_group_issues:
                print(f"Issues found for instance {instance_id}:")
                for issue in security_group_issues:
                    print(f"  - {issue}")

def check_ami_security(ami_id):
    # You can implement additional checks against a list of secure AMIs or query a compliance service
    # Here we're just returning False for demonstration purposes
    outdated_amis = ['ami-0123456789abcdef0']  # Example outdated AMI IDs
    return ami_id not in outdated_amis

if __name__ == "__main__":
    check_ec2_instances()
