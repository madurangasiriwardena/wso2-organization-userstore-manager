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

package org.wso2.carbon.custom.userstore.manager.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.custom.userstore.manager.internal.CustomUserStoreDataHolder;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationAuthorizationDao;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationAuthorizationDaoImpl;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

public class Utils {

    private static final Log log = LogFactory.getLog(Utils.class);

    public static boolean isAuthorized(String organizationId, String permission)
            throws org.wso2.carbon.user.core.UserStoreException {

        // To create a user inside an organization
        // you should have '/permission/admin/organizations/create' over the subject organization
        OrganizationAuthorizationDao authorizationDao = new OrganizationAuthorizationDaoImpl();
        try {
            return authorizationDao.isUserAuthorized(getAuthenticatedUserId(), organizationId, permission);
        } catch (OrganizationManagementException | UserStoreException e) {
            String errorMsg =
                    "Error while authorizing the action : " + permission + ", organization id : " + organizationId;
            log.error(errorMsg, e);
            throw new org.wso2.carbon.user.core.UserStoreException(errorMsg, e);
        }
    }

    public static String getUserIDFromUserName(String username, int tenantId) throws UserStoreException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CustomUserStoreDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            return userStoreManager.getUserIDFromUserName(username);
        } catch (UserStoreException e) {
            String errorMsg = "Error obtaining ID for the username : " + username + ", tenant id : " + tenantId;
            throw new UserStoreException(errorMsg, e);
        }
    }

    public static String getAuthenticatedUserId() throws UserStoreException {

        return getUserIDFromUserName(getAuthenticatedUsername(), getTenantId());
    }

    public static String getAuthenticatedUsername() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    public static int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }
}
