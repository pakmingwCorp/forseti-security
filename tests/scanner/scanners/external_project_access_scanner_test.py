# Copyright 2018 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for ExternalProjectAccessScanner."""
from datetime import datetime
import json
import unittest
import mock

from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.scanner.scanners.external_project_access_scanner import ExternalProjectAccessScanner
from google.cloud.forseti.scanner.scanners.external_project_access_scanner import SCOPES
from google.cloud.forseti.scanner.scanners.external_project_access_scanner import UserCloudResourceManagerClient

from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path

TEST_PROJECT_LIST = [{
        "projects": [
            {
            "projectNumber": "123456789012",
            "projectId": "test_project_1",
            "lifecycleState": "ACTIVE",
            "name": "test_project_1",
            "createTime": "2018-09-21T11:46:53Z",
            "parent": {
                "type": "organization",
                "id": "1234567"
                }
            },
            {
            "projectNumber": "234567890123",
            "projectId": "test_project_2",
            "lifecycleState": "ACTIVE",
            "name": "test_project_2",
            "createTime": "2018-09-20T12:20:29.764Z",
            "parent": {
                "type": "organization",
                "id": "1234567"
            }
            },
            {
            "projectNumber": "345678901234",
            "projectId": "test_project_3",
            "lifecycleState": "DELETE_REQUESTED",
            "name": "test_project_3",
            "createTime": "2018-09-15T15:28:10.406Z",
            "parent": {
                "type": "organization",
                "id": "1234567"
            }
            },
            {
            "projectNumber": "456789012345",
            "projectId": "test_project_4",
            "lifecycleState": "ACTIVE",
            "name": "test_project_4",
            "createTime": "2018-09-11T19:09:34.093Z",
            "parent": {
                "type": "organization",
                "id": "1234567"
            }
            },
            {
            "projectNumber": "567890123456",
            "projectId": "test_project_5",
            "lifecycleState": "ACTIVE",
            "name": "test_project_5",
            "createTime": "2018-09-10T17:32:26.918Z",
            "parent": {
                "type": "folder",
                "id": "0987654321"
            }
            }
        ]
        }]

TEST_ANCESTRIES_ONE = [
                        {'resourceId': 
                            {'id': 'test_project_1',
                             'type': 'project'},
                        },
                        {'resourceId': 
                            {'id': '1234567',
                             'type': 'organization'},
                        },

                    ]

TEST_ANCESTRIES_TWO = [
                        {'resourceId': 
                            {'id': 'test_project_1',
                             'type': 'project'},
                        },
                        {'resourceId': 
                            {'id': '0987654321',
                             'type': 'folder'},
                        },
                        {'resourceId': 
                            {'id': '7654321',
                             'type': 'organization'},
                        },

                    ]

class UserCloudResourceManagerClientTest(ForsetiTestCase):
    
    @mock.patch("google.cloud.forseti.scanner.scanners.external_project_access_scanner.UserCloudResourceManagerClient.delegated_credential")
    def setUp(self, mocked_delegated_credentials):
        
        ancestries = [TEST_ANCESTRIES_ONE, 
                      TEST_ANCESTRIES_ONE, 
                      TEST_ANCESTRIES_ONE,
                      TEST_ANCESTRIES_ONE,
                      TEST_ANCESTRIES_TWO]

        inventory_configs = mock.MagicMock()
        self.user_crm_client = UserCloudResourceManagerClient("user1@example.com",
                                                         inventory_configs,
                                                         SCOPES)
        self.user_crm_client.get_project_ancestry = mock.MagicMock(side_effect=ancestries)

        self.user_crm_client.get_projects = mock.MagicMock(return_value=TEST_PROJECT_LIST)

    
    def test_list_projects(self):
        
        ids_to_test = ["test_project_1", 
                       "test_project_2",
                       "test_project_3", 
                       "test_project_4", 
                       "test_project_5"]

        for proj_id in self.user_crm_client.project_ids:
            self.assertIn(proj_id, ids_to_test)

        for proj_id in ids_to_test:
            self.assertIn(proj_id, self.user_crm_client.project_ids)

    def test_get_project_ancestry_resources(self):
        ancestries = self.user_crm_client.get_project_ancestry_resources("test_project_1")

        self.assertTrue(isinstance(ancestries, list))

        self.assertTrue(isinstance(ancestries[0], Project))
        self.assertTrue(isinstance(ancestries[1], Organization))

"""


class ExternalProjectAccessScannerTest(ForsetiTestCase):

    

    
    MOCK_RESULTS = [TEST_ANCESTRIES_BAD, TEST_ANCESTRIES_GOOD]

    MOCK_EMAILS = ['user1@example.com', 'user2@example.com']

    def setUp(self):
        global_configs = dict()
        scanner_configs = dict(output_path="gs://test-forseti-dev/scanner/output",
                               rules_path=__file__,
                               scanners=[dict(name='external_project_access', enabled=True)])
        service_configs = mock.MagicMock()
        model_name = "TestModel"
        snapshot_timestamp = datetime.now().strftime("%Y%m%dT%H%M%SZ")
        rules = get_datafile_path(__file__, 'external_project_access_test_rules_1.yaml')
        
        self.scanner = ExternalProjectAccessScanner(global_configs,
                                                    scanner_configs,
                                                    service_configs,
                                                    model_name,
                                                    snapshot_timestamp,
                                                    rules)
        
        
 """