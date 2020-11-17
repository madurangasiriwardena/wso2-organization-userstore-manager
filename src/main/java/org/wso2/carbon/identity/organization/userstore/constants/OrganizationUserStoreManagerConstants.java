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
        ERROR_WHILE_GETTING_ORG("ORGUMGT_00004", "Error while obtaining organization Id"),
        ERROR_WHILE_GETTING_ORG_META("ORGUMGT_00005", "Error while obtaining organization metadata"),
        ERROR_WHILE_PAGINATED_SEARCH("ORGUMGT_00006", "Error occurred while performing paginated search.")
        ;

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
