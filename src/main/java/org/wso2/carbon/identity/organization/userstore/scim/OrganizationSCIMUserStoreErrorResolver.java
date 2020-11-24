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

package org.wso2.carbon.identity.organization.userstore.scim;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpStatus;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreErrorResolver;
import org.wso2.carbon.identity.scim2.common.extenstion.SCIMUserStoreException;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * SCIM User Store error resolver impl for the organization mgt user store manager.
 */
public class OrganizationSCIMUserStoreErrorResolver implements SCIMUserStoreErrorResolver {

    @Override
    public SCIMUserStoreException resolve(UserStoreException e) {

        if (e instanceof org.wso2.carbon.user.core.UserStoreException) {
            org.wso2.carbon.user.core.UserStoreException e1 = (org.wso2.carbon.user.core.UserStoreException) e;
            if (StringUtils.isNotEmpty(e1.getErrorCode())) {
                int httpStatusCode = getErrorMessageByErrorCode(e1.getErrorCode());
                if (httpStatusCode != -1) {
                    return new SCIMUserStoreException(e.getMessage(), httpStatusCode);
                }
            }
        }
        return null;
    }

    @Override
    public int getOrder() {

        return 10;
    }

    public int getErrorMessageByErrorCode(String errorCode) {

        switch (errorCode) {
            case "ORGUMGT_00001":
            case "ORGUMGT_00004":
            case "ORGUMGT_00005":
            case "ORGUMGT_00006":
            case "ORGUMGT_00007":
            case "ORGUMGT_00009":
            case "ORGUMGT_00010":
            case "ORGUMGT_00011":
            case "ORGUMGT_00012":
            case "ORGUMGT_00013":
            case "ORGUMGT_00014":
            case "ORGUMGT_00015":
            case "ORGUMGT_00016":
            case "ORGUMGT_00017":
            case "ORGUMGT_00018":
            case "ORGUMGT_00019":
            case "ORGUMGT_00020":
            case "ORGUMGT_00021":
                return HttpStatus.SC_INTERNAL_SERVER_ERROR;
            case "ORGUMGT_00002":
            case "ORGUMGT_00008":
                return HttpStatus.SC_BAD_REQUEST;
            case "ORGUMGT_00003":
                return HttpStatus.SC_FORBIDDEN;
            default:
                return -1;
        }
    }
}
