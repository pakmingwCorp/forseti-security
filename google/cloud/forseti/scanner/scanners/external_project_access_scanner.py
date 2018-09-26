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

"""External project access scanner."""
# pylint: disable=line-too-long
import time
import itertools

from google.auth.exceptions import RefreshError
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.gcp_api.api_helpers import get_delegated_credential # noqa=E501
from google.cloud.forseti.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient # noqa=E501
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.scanner.audit import external_project_access_rules_engine as epa_rules_engine # noqa=E501
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.inventory.storage import Storage
# pylint: enable=line-too-long

LOGGER = logger.get_logger(__name__)

SCOPES = ['https://www.googleapis.com/auth/cloudplatformprojects.readonly']


class ExternalProjectAccessScanner(base_scanner.BaseScanner):
    """Scanner for external project access."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(ExternalProjectAccessScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)

        self.inventory_configs = self.service_config.get_inventory_config()
        self.rules_engine = \
            epa_rules_engine.ExternalProjectAccessRulesEngine(
                rules_file_path=self.rules,
                snapshot_timestamp=self.snapshot_timestamp
            )
        self.rules_engine.build_rule_book(self.inventory_configs)

        self._ancestries = dict()

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): A list of violations.
        """
        all_violations = self._flatten_violations(all_violations)

        self._output_results_to_db(all_violations)

    def _find_violations(self, ancestries_by_user):
        """Find violations in the policies.

        Args:
            ancestries_by_user (dict): The project ancestries collected
                                               from the scanner
        Returns:
            list: A list of ExternalProjectAccess violations
        """
        all_violations = []
        LOGGER.info('Finding project access violations...')

        for user_mail, project_ancestries in ancestries_by_user.iteritems():

            for project_ancestry in project_ancestries:
                violations = \
                    self.rules_engine.find_policy_violations(user_mail,
                                                             project_ancestry)
                all_violations.extend(violations)

        return all_violations

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:

            violation_data = {
                'full_name': violation.full_name,
                'member': violation.member,
                'rule_ancestor': violation.rule_ancestor.name
            }

            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'resource_data': violation.resource_data
            }

    def _project_ancestries_by_user(self, user_email):
        """Retrieves the list of ancestries for a user.

        Args:
            user_email (str): The e-mail address against which
                              to query.
        Returns:
            list: List of list of resource ancestry chains.
        """
        ancestries = []
        user_creds = get_delegated_credential(user_email, SCOPES)
        # Get the resource manager client
        crm_client = CloudResourceManagerClient(
            global_configs=self.inventory_configs,
            credentials=user_creds)
        # Get a list of project ID's
        project_id_result = [[project['projectId']
                              for project in projects['projects']]
                             for projects in crm_client.get_projects()]

        project_ids = itertools.chain.from_iterable(project_id_result)

        # For each of the project ID's we will get the ancestry
        for project_id in project_ids:
            # To increase speed, we'll keep track of the projects
            # for which we have already queried the ancestry.
            if project_id not in self._ancestries.keys():
                self._ancestries[project_id] = []
                # We'll create Resource objects for each resource
                for resource in crm_client.get_project_ancestry(project_id):
                    self._ancestries[project_id].append(
                        resource_util.create_resource(
                            resource['resourceId']['id'],
                            resource['resourceId']['type']
                        )
                    )
            ancestries.append(self._ancestries[project_id])
        return ancestries

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            dict: User project relationship.
        """
        member_type_list = [
            'gsuite_user_member'
        ]
        project_ancestries_by_user = dict()
        user_count = 0
        with self.service_config.scoped_session() as session:
            inventory_index_id = \
                DataAccess.get_latest_inventory_index_id(session)

            inventory_storage = \
                Storage(session, inventory_index_id, readonly=True)
            inventory_storage.open()

            start_time = time.time()

            for inventory_row in \
                    inventory_storage.iter(type_list=member_type_list):

                user_count += 1
                user_email = inventory_row.get_resource_data()['email']

                try:
                    project_ancestries_by_user[user_email] = \
                        self._project_ancestries_by_user(user_email)
                except KeyError:
                    LOGGER.debug('User %s doesn\'t have any projects.',
                                 user_email)
                except RefreshError:
                    LOGGER.debug('Couldn\'t retrieve projects for user %s',
                                 user_email)

            elapsed_time = time.time() - start_time

            LOGGER.debug('It took %f seconds to query projects for %d users',
                         elapsed_time,
                         user_count)

        return project_ancestries_by_user

    def run(self):
        """Runs the data collection."""
        project_ancestries_by_user = self._retrieve()
        all_violations = self._find_violations(project_ancestries_by_user)
        self._output_results(all_violations)
