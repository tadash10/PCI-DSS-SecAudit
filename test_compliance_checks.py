import unittest
from unittest.mock import patch, MagicMock
from compliance_script import check_ami_security, check_security_groups, check_access_control

class TestComplianceChecks(unittest.TestCase):

    @patch('compliance_script.boto3.client')
    def test_check_ami_security(self, mock_boto_client):
        outdated_amis = ['ami-0123456789abcdef0']
        self.assertTrue(check_ami_security('ami-0987654321abcdef0', outdated_amis))  # Not outdated
        self.assertFalse(check_ami_security('ami-0123456789abcdef0', outdated_amis
