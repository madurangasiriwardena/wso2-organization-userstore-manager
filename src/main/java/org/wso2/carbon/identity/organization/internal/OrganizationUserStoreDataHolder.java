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

package org.wso2.carbon.identity.organization.internal;

import org.wso2.carbon.identity.organization.mgt.core.OrganizationManager;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationAuthorizationDao;
import org.wso2.carbon.user.core.service.RealmService;

public class OrganizationUserStoreDataHolder {

    private static OrganizationUserStoreDataHolder dataHolder = new OrganizationUserStoreDataHolder();
    private RealmService realmService;
    private OrganizationManager organizationService;
    private OrganizationAuthorizationDao organizationAuthDao;

    public OrganizationAuthorizationDao getOrganizationAuthDao() {
        return organizationAuthDao;
    }

    public void setOrganizationAuthDao(OrganizationAuthorizationDao organizationAuthDao) {

        this.organizationAuthDao = organizationAuthDao;
    }

    public static OrganizationUserStoreDataHolder getInstance() {

        return dataHolder;
    }

    public void setDataHolder(OrganizationUserStoreDataHolder dataHolder) {

        this.dataHolder = dataHolder;
    }

    public RealmService getRealmService() {

        return realmService;
    }

    public void setRealmService(RealmService realmService) {

        this.realmService = realmService;
    }

    public OrganizationManager getOrganizationService() {

        return organizationService;
    }

    public void setOrganizationService(OrganizationManager organizationService) {

        this.organizationService = organizationService;
    }
}
