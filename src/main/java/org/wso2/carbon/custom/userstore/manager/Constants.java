/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.custom.userstore.manager;

public class Constants {

    /**
     *  <IS_HOME>/repository/resources/conf/templates/repository/conf/identity/identity.xml.j2
     *
     *     <!--Organization management properties-->
     *     <OrganizationMgt>
     *             <OrgNameClaimUri>{{organization.mgt.org_name_claim_uri}}</OrgNameClaimUri>
     *             <OrgIdClaimUri>{{organization.mgt.org_id_claim_uri}}</OrgIdClaimUri>
     *     </OrganizationMgt>
     *
     *  <IS_HOME>>/repository/conf/deployment.toml
     *
     *      [organization.mgt]
     *      org_name_claim_uri = "http://wso2.org/claims/organizationName"
     *      org_id_claim_uri = "http://wso2.org/claims/organizationId"
     */
    public static final String ORGANIZATION_NAME_CLAIM_URI = "OrganizationMgt.OrgNameClaimUri";
    public static final String ORGANIZATION_ID_CLAIM_URI = "OrganizationMgt.OrgIdClaimUri";
    public static final String ORGANIZATION_NAME_DEFAULT_CLAIM_URI = "http://wso2.org/claims/organization";
    public static final String ORGANIZATION_ID_DEFAULT_CLAIM_URI = "http://wso2.org/claims/organizationId";
    public static final String ROOT_ORG_NAME = "ROOT";

    public static final String ORGANIZATION_USER_CREATE_PERMISSION = "/permission/admin/manage/identity/usermgt/create";
}
