import unittest
from unittest.mock import patch, MagicMock
from compliance_script import check_ami_security, check_security_groups, check_access_control

class TestComplianceChecks(unittest.TestCase):

    @patch('compliance_script.boto3.client')
    def test_check_ami_security(self, mock_boto_client):
        outdated_amis = ['ami-0123456789abcdef0']
        self.assertTrue(check_ami_security('ami-0987654321abcdef0', outdated_amis))  # Not outdated
        self.assertFalse(check_ami_security('ami-0123456789abcdef0', outdated_amis))  # Outdated

    def test_check_security_groups(self):
        security_groups = {
            'sg-0123456789': {
                'IpPermissions': [
                    {'IpProtocol': '-1'},  # All traffic
                    {'IpProtocol': 'tcp', 'FromPort': 22, 'IpRanges': [{'CidrIp': '0.0.0.0/0'}]}
                ]
            }
        }
        instance_sgs = [{'GroupId': 'sg-0123456789'}]
        issues = check_security_groups(security_groups, instance_sgs, '0.0.0.0/0')
        self.assertIn("Security group sg-0123456789 allows all inbound traffic.", issues)
        self.assertIn("Security group sg-0123456789 allows SSH access from 0.0.0.0/0.", issues)

    @patch('compliance_script.boto3.client')
    def test_check_access_control(self, mock_boto_client):
        iam_client = MagicMock()
        iam_client.get_instance_profile.return_value = {
            'InstanceProfile': {
                'Roles': [{'RoleName': 'test-role'}]
            }
        }
        iam_client.list_attached_role_policies.return_value = {
            'AttachedPolicies': [{'PolicyName': 'AWSElasticBeanstalkWebTier'}]
        }
        
        with patch('compliance_script.boto3.client', return_value=iam_client):
            issues = check_access_control('i-0123456789abcdef0', iam_client)
            self.assertIn("IAM role test-role has overly permissive policy: AWSElasticBeanstalkWebTier.", issues)

if __name__ == '__main__':
    unittest.main()
