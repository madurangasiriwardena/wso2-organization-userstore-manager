/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.organization.userstore.constants;

public class OrganizationUserStoreManagerConstants {

    public enum ErrorMessage {

        ERROR_OBTAINING_CLAIMS("ORGUMGT_00001", "Error obtaining organization claim/attribute mappings"),
        ERROR_ORG_NOT_FOUND("ORGUMGT_00002", "Couldn't find an organization associated with the provided" +
                " organization identifier: %s"),
        ERROR_NOT_AUTHORIZED("ORGUMGT_00003", "Authenticated user is not authorized to perform this action."),
        ERROR_WHILE_GETTING_ORG("ORGUMGT_00004", "Error while obtaining organization details."),
        ERROR_WHILE_MOVING_LDAP_ENTRY("ORGUMGT_00005", "Error while moving the LDAP entry. user id: %s"),
        ERROR_WHILE_PAGINATED_SEARCH("ORGUMGT_00006", "Error occurred while performing paginated search."),
        ERROR_WHILE_PAGINATED_SEARCH_CONTROLS("ORGUMGT_00007", "Error occurred while setting paged results " +
                "controls for paginated search, %s"),
        ERROR_ORG_NOT_ACTIVE("ORGUMGT_00008", "Organization is not active: %s"),
        ERROR_ACCESSING_DIR_CONTEXT("ORGUMGT_00009", "Cannot access the directory context"),
        ERROR_WHILE_ROLE_UPDATE("ORGUMGT_00010", "User: %s was added but an error occurred while " +
                "updating the role list."),
        ERROR_RESOLVING_DN("ORGUMGT_00011", "Couldn't resolve new or old DN. newDn: %s, oldDn: %s"),
        ERROR_WHILE_ORG_MOVE("ORGUMGT_00012", "Error while moving the organization of the user: %s"),
        ERROR_CREATING_DN("ORGUMGT_00013", "Error while creating the DN: %s"),
        ERROR_DELETING_DN("ORGUMGT_00014", "Error while deleting the DN: %s"),
        ERROR_GETTING_AUTHORIZED_ORG("ORGUMGT_00015", "Error while retrieving authorized organizations. Permission: %s"),
        ERROR_GETTING_AUTHENTICATED_USER("ORGUMGT_00016", "Error while retrieving authenticated user id: %s"),
        ERROR_CHECKING_FOR_ADMIN("ORGUMGT_00017", "Error while checking if the authorized user is an admin"),
        ERROR_SEARCHING_WITH_FILTER("ORGUMGT_00018", "Error occurred while searching for user(s) for filter: %s"),
        ERROR_EXTRACTING_USERS("ORGUMGT_00019", "Error occurred while extracting users from search results."),
        ERROR_READING_USER_INFO("ORGUMGT_00020", "Error in reading user information in the user store for the user %s"),
        ERROR_CLAIM_FILTERING("ORGUMGT_00021", "Error occurred while doing claim filtering for user(s) with filter: %s");

        private final String code;
        private final String message;

        ErrorMessage(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }
    }
}
