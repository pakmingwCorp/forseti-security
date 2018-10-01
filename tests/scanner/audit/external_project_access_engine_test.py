# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Tests the CloudSqlRulesEngine."""

import json
import unittest
import traceback
import mock
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit import errors
from google.cloud.forseti.scanner.audit import external_project_access_rules_engine as epare
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.services.inventory.base import resources
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.gcp_type.folder import Folder

class ExternalProjectAccessRulesEngineTest(ForsetiTestCase):

    TEST_ANCESTRIES = {'user1@example.com': [Project('13579'), Folder('24680'), Organization('567890')],
                       'user2@example.com': [Project('13579'), Folder('0987654321'), Organization('1357924680')]}
    TEST_ANCESTRIES_SIMPLE = {'user1@example.com': [Project('13579'), Organization('567890')]}
    TEST_ANCESTRIES_VIOLATIONS = {'user2@example.com': [Project('13579'), Folder('24680'), Organization('1357924680')]}

    def setUp(self):
        self.epare = epare
        self.epare.LOGGER = mock.MagicMock()
        self.inventory_config = mock.MagicMock()
        self.inventory_config.get_root_resource_id = mock.MagicMock(return_value='organizations/567890')


    def test_default_rule_added_with_no_rules_in_file(self):
        """Test that a RuleBook is built correctly with an empty yaml file."""
        rules_local_path = get_datafile_path(__file__,
            'external_project_access_test_rules_0.yaml')
        rules_engine = epare.ExternalProjectAccessRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__,
            'external_project_access_test_rules_1.yaml')
        rules_engine = epare.ExternalProjectAccessRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        self.assertEqual(3, len(rules_engine.rule_book.resource_rules_map))
    
    def test_build_rule_book_from_local_yaml_file_bad_ancestor(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__,
            'external_project_access_test_rules_2.yaml')
        rules_engine = epare.ExternalProjectAccessRulesEngine(rules_file_path=rules_local_path)
        with self.assertRaises(errors.InvalidRulesSchemaError):
            rules_engine.build_rule_book(self.inventory_config)

    def test_no_viloations(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        all_violations = []
        rules_local_path = get_datafile_path(__file__,
            'external_project_access_test_rules_1.yaml')
        rules_engine = epare.ExternalProjectAccessRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        for user, ancestry in self.TEST_ANCESTRIES.iteritems():
            violations = rules_engine.find_policy_violations(user, ancestry)
            all_violations.extend(violations)
        self.assertEqual(len(all_violations), 0)

    def test_no_viloations_no_rules(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        all_violations = []
        rules_local_path = get_datafile_path(__file__,
            'external_project_access_test_rules_0.yaml')
        rules_engine = epare.ExternalProjectAccessRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        for user, ancestry in self.TEST_ANCESTRIES_SIMPLE.iteritems():
            violations = rules_engine.find_policy_violations(user, ancestry)
            all_violations.extend(violations)
        self.assertEqual(len(all_violations), 0)

    def test_yes_viloations(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        all_violations = []
        rules_local_path = get_datafile_path(__file__,
            'external_project_access_test_rules_1.yaml')
        rules_engine = epare.ExternalProjectAccessRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        for user, ancestry in self.TEST_ANCESTRIES_VIOLATIONS.iteritems():
            violations = rules_engine.find_policy_violations(user, ancestry)
            all_violations.extend(violations)
        self.assertEqual(len(all_violations), 3)


class ExternalProjectAccessRuleBookTest(ForsetiTestCase):
    """Tests for the ExternalProjectAccessRuleBook."""

    TEST_GOOD_RULE = dict(name='default', ancestor='organizations/567890')
    TEST_BAD_RULE = dict(name='default', ancestor='policy/12345')
    TEST_RULE_DEFS = dict(rules=[TEST_GOOD_RULE])

    def setUp(self):
        """Set up."""
        self.rule_index = 0
        self.epare = epare
        self.epare.LOGGER = mock.MagicMock()
        self.inventory_config = mock.MagicMock()
        
        self.inventory_config.get_root_resource_id = mock.MagicMock(return_value='organizations/567890')
        self.rule_book = epare.ExternalProjectAccessRuleBook(self.inventory_config)

    def test_validate_good_ancestor(self):
        try:
            self.rule_book.validate_ancestor(ExternalProjectAccessRuleBookTest.TEST_GOOD_RULE['ancestor'], 0)
        except:
            self.fail("Unexpected exception thrown")
    
    def test_validate_bad_ancestor(self):
        with self.assertRaises(errors.InvalidRulesSchemaError): 
            self.rule_book.validate_ancestor(ExternalProjectAccessRuleBookTest.TEST_BAD_RULE['ancestor'], 0)

    def test_process_good_rule(self):
        try:
            resource = self.rule_book.process_rule(ExternalProjectAccessRuleBookTest.TEST_GOOD_RULE, 0)
            self.assertEqual(resource.id, '567890')
            self.assertTrue(isinstance(resource, Organization))
        except Exception as e:
            self.fail("Unexpected exception thrown: " + str(e))

    def test_process_bad_rule(self):
        with self.assertRaises(errors.InvalidRulesSchemaError): 
            self.rule_book.process_rule(ExternalProjectAccessRuleBookTest.TEST_BAD_RULE, 0)

    def test_add_rule(self):
        self.rule_book.add_rule(ExternalProjectAccessRuleBookTest.TEST_GOOD_RULE, 0)
        self.assertEqual(1, len(self.rule_book.resource_rules_map))

    def test_add_rules(self):
        self.rule_book.add_rules(self.TEST_RULE_DEFS)
        self.assertEqual(1, len(self.rule_book.resource_rules_map))