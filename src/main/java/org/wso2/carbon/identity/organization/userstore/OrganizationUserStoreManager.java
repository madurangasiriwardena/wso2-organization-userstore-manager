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

package org.wso2.carbon.identity.organization.userstore;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.organization.userstore.internal.OrganizationUserStoreDataHolder;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.mgt.core.OrganizationManager;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationAuthorizationDao;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementClientException;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.mgt.core.model.Organization;
import org.wso2.carbon.identity.organization.mgt.core.model.UserStoreConfig;
import org.wso2.carbon.identity.organization.mgt.core.usermgt.AbstractOrganizationMgtUserStoreManager;
import org.wso2.carbon.identity.organization.userstore.util.Utils;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.UniqueIDPaginatedSearchResult;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.ldap.LDAPConstants;
import org.wso2.carbon.user.core.ldap.LDAPSearchSpecification;
import org.wso2.carbon.user.core.model.Condition;
import org.wso2.carbon.user.core.model.ExpressionAttribute;
import org.wso2.carbon.user.core.model.ExpressionCondition;
import org.wso2.carbon.user.core.model.ExpressionOperation;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.JNDIUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.stream.Collectors;

import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.SortControl;
import org.wso2.carbon.identity.organization.userstore.constants.OrganizationUserStoreManagerConstants.ErrorMessage;

import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.DN;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.FILTER_USERS_BY_ORG_NAME;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.ORGANIZATION_ADMIN_PERMISSION;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.ORGANIZATION_ID_CLAIM_URI;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.ORGANIZATION_ID_DEFAULT_CLAIM_URI;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.ORGANIZATION_NAME_CLAIM_URI;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.ORGANIZATION_NAME_DEFAULT_CLAIM_URI;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.ROOT;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.UI_EXECUTE;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.USER_MGT_CREATE_PERMISSION;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.USER_MGT_LIST_PERMISSION;
import static org.wso2.carbon.identity.organization.userstore.constants.OrganizationUserStoreManagerConstants.ErrorMessage.ERROR_PERSISTING_USER;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME;
import static org.wso2.carbon.user.core.UserStoreConfigConstants.maxUserNameListLength;

public class OrganizationUserStoreManager extends AbstractOrganizationMgtUserStoreManager {

    private static final Log log = LogFactory.getLog(OrganizationUserStoreManager.class);

    private static final String PROPERTY_REFERRAL_IGNORE = "ignore";
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";

    public OrganizationUserStoreManager() {
    }

    public OrganizationUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
            ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
    }

    public OrganizationUserStoreManager(RealmConfiguration realmConfig, ClaimManager claimManager,
            ProfileConfigurationManager profileManager) throws UserStoreException {

        super(realmConfig, claimManager, profileManager);
    }

    @Override
    public User doAddUserWithID(String userName, Object credential, String[] roleList, Map<String, String> claims,
            String profileName, boolean requirePasswordChange) throws UserStoreException {

        String userID = getUniqueUserID();
        persistUser(userID, userName, credential, roleList, claims);
        if (isUserIdGeneratedByUserStore(userName, claims)) {
            //If the userId attribute is immutable then we need to retrieve the userId from the user store.
            return getUser(null, userName);
        }
        return getUser(userID, userName);
    }

    @Override
    protected UniqueIDPaginatedSearchResult doGetUserListWithID(Condition condition, String profileName, int limit,
            int offset, String sortBy, String sortOrder) throws UserStoreException {

        UniqueIDPaginatedSearchResult result = new UniqueIDPaginatedSearchResult();
        // Since we support only 'AND' operation, can get expressions as a list.
        List<ExpressionCondition> expressionConditions = getExpressionConditions(condition);
        // Get organization id and organization name claim URIs
        String orgNameClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_NAME_CLAIM_URI)) ?
                IdentityUtil.getProperty(ORGANIZATION_NAME_CLAIM_URI).trim() :
                ORGANIZATION_NAME_DEFAULT_CLAIM_URI;
        String orgIdClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_ID_CLAIM_URI)) ?
                IdentityUtil.getProperty(ORGANIZATION_ID_CLAIM_URI).trim() :
                ORGANIZATION_ID_DEFAULT_CLAIM_URI;
        // Find respective attribute names
        String orgNameAttribute, orgIdAttribute;
        try {
            int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            org.wso2.carbon.user.api.UserRealm tenantUserRealm = OrganizationUserStoreDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(tenantId);
            org.wso2.carbon.user.api.ClaimManager claimManager = tenantUserRealm.getClaimManager();
            orgNameAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgNameClaimUri);
            orgIdAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgIdClaimUri);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_OBTAINING_CLAIMS;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        }

        String orgSearchBase = null;
        boolean nameAsIdentifier = false;
        String orgIdentifier = null;
        // Find the organization DN (search base)
        // Find the organization identifier from the search conditions
        for (int i = 0; i < expressionConditions.size(); i++) {
            if (expressionConditions.get(i).getAttributeName().equals(orgNameAttribute)) {
                // Received organization name as the identifier
                nameAsIdentifier = true;
                orgIdentifier = expressionConditions.get(i).getAttributeValue().trim();
                // Organization name shouldn't be considered as a search condition.
                expressionConditions.remove(i);
                break;
            } else if (expressionConditions.get(i).getAttributeName().equals(orgIdAttribute)) {
                // Received organization id as the identifier
                orgIdentifier = expressionConditions.get(i).getAttributeValue().trim();
                // Organization id shouldn't be considered as a search condition.
                expressionConditions.remove(i);
                break;
            }
        }
        // If organization is defined in the request, find the organization DN
        if (orgIdentifier != null) {
            // Resolve organization identifier
            OrganizationManager orgService = OrganizationUserStoreDataHolder.getInstance().getOrganizationService();
            try {
                orgIdentifier = nameAsIdentifier ? orgService.getOrganizationIdByName(orgIdentifier): orgIdentifier;
            } catch (OrganizationManagementClientException e) {
                String msg = String.format(ErrorMessage.ERROR_ORG_NOT_FOUND.getMessage(), orgIdentifier);
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
                throw new UserStoreException(msg, ErrorMessage.ERROR_ORG_NOT_FOUND.getCode(), e);
            } catch (OrganizationManagementException e) {
                ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_GETTING_ORG;
                log.error(errorMessage.getMessage(), e);
                throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
            }
            // Resolve user search base
            try {
                // Get user store configs by organization ID
                orgSearchBase = orgService.getUserStoreConfigs(orgIdentifier).get(DN).getValue();
            } catch (OrganizationManagementException e) {
                ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_GETTING_ORG;
                log.error(errorMessage.getMessage(), e);
                throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
            }
        }

        LDAPSearchSpecification ldapSearchSpecification = new LDAPSearchSpecification(realmConfig,
                expressionConditions);
        boolean isMemberShipPropertyFound = ldapSearchSpecification.isMemberShipPropertyFound();
        limit = getLimit(limit, isMemberShipPropertyFound);
        offset = getOffset(offset);
        if (limit == 0) {
            return result;
        }
        int pageSize = limit;
        DirContext dirContext = this.connectionSource.getContext();
        LdapContext ldapContext = (LdapContext) dirContext;
        List<User> users;
        List<String> ldapUsers = new ArrayList<>();
        String userNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        boolean filterByOrgName = Boolean.valueOf(IdentityUtil.getProperty(FILTER_USERS_BY_ORG_NAME));
        String orgIdentifierAttribute = filterByOrgName ? orgNameAttribute : orgIdAttribute;
        try {
            ldapContext.setRequestControls(new Control[] {
                    new PagedResultsControl(pageSize, Control.CRITICAL),
                    new SortControl(userNameAttribute, Control.NONCRITICAL)
            });
            users = performLDAPSearch(ldapContext, ldapSearchSpecification, orgSearchBase, orgIdentifierAttribute,
                    pageSize, offset, expressionConditions, filterByOrgName);
            result.setUsers(users);
            return result;
        } catch (NamingException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_PAGINATED_SEARCH;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } catch (IOException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_PAGINATED_SEARCH_CONTROLS;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } finally {
            JNDIUtil.closeContext(dirContext);
            JNDIUtil.closeContext(ldapContext);
        }
    }

    @Override
    public List<String> doGetUserListFromPropertiesWithID(String property, String value, String profileName)
            throws UserStoreException {

        // Server startup calls this legacy API even before this user store manager is activated.
        // Call super during such scenarios
        // Child classes who override this method should duplicate the below logic
        if (!OrganizationUserStoreDataHolder.getInstance().isActive()) {
            return super.doGetUserListFromPropertiesWithID(property, value, profileName);
        }
        // Use the same API to access the LDAP even when the pagination parameters are not present in the request
        Condition condition = new ExpressionCondition("EQ", property, value);
        int maxUserListLength =
                Integer.valueOf(this.getRealmConfiguration().getUserStoreProperty(maxUserNameListLength));
        UniqueIDPaginatedSearchResult result = doGetUserListWithID(condition, profileName, maxUserListLength, 1, null, null);
        return result.getUsers().stream().map(user -> user.getUserID()).collect(Collectors.toList());
    }

    @Override
    protected String doGetUserIDFromUserNameWithID(String userName) throws UserStoreException {

        String userNameProperty = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        return getUserIDFromProperty(userNameProperty, userName);
    }

    @Override
    protected void doSetUserAttributesWithID(String userID, Map<String, String> processedClaimAttributes,
            String profileName) throws UserStoreException {

        // Get organization id and organization name claim URIs
        String orgNameClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_NAME_CLAIM_URI)) ?
                IdentityUtil.getProperty(ORGANIZATION_NAME_CLAIM_URI).trim() :
                ORGANIZATION_NAME_DEFAULT_CLAIM_URI;
        String orgIdClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_ID_CLAIM_URI)) ?
                IdentityUtil.getProperty(ORGANIZATION_ID_CLAIM_URI).trim() :
                ORGANIZATION_ID_DEFAULT_CLAIM_URI;
        // Find respective attribute names
        String orgNameAttribute, orgIdAttribute;
        try {
            int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
            org.wso2.carbon.user.api.UserRealm tenantUserRealm = OrganizationUserStoreDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(tenantId);
            org.wso2.carbon.user.api.ClaimManager claimManager = tenantUserRealm.getClaimManager();
            orgNameAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgNameClaimUri);
            orgIdAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgIdClaimUri);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_OBTAINING_CLAIMS;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        }
        // Check if patching organization name or organization id
        boolean patchById = processedClaimAttributes != null && processedClaimAttributes.containsKey(orgIdAttribute);
        boolean patchByName = processedClaimAttributes != null
                && processedClaimAttributes.containsKey(orgNameAttribute);
        if (!(patchById || patchByName)) {
            // Not an organization id/name attribute patching
            super.doSetUserAttributesWithID(userID, processedClaimAttributes, profileName);
            return;
        }
        // TODO check if both id and name sent in request.
        String orgIdentifier = patchById ? processedClaimAttributes.get(orgIdAttribute) :
                processedClaimAttributes.get(orgNameAttribute);
        orgIdentifier = StringUtils.trim(orgIdentifier);
        String orgId, orgName;
        OrganizationManager organizationManager = OrganizationUserStoreDataHolder.getInstance().getOrganizationService();
        Organization organization;
        try {
            // Get organization id
            orgId = patchByName && !patchById ? organizationManager.getOrganizationIdByName(orgIdentifier) :
                    orgIdentifier;
            organization = organizationManager.getOrganization(orgId, false);
        } catch (OrganizationManagementClientException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ORG_NOT_FOUND;
            throw new UserStoreException(
                    String.format(errorMessage.getMessage(), orgIdentifier),
                    errorMessage.getCode(), e);
        } catch (OrganizationManagementException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_GETTING_ORG;
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        }
        // Permission check for the new organization
        // ROOT organization is system created. Therefore, no user to authorize at that moment
        if (getAuthenticatedUsername() != null && !isAuthorized(organization.getId(), USER_MGT_CREATE_PERMISSION)) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_NOT_AUTHORIZED;
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode());
        }
        // Set user claims to be patched
        orgName = patchById ? organization.getName(): orgIdentifier;
        processedClaimAttributes.put(orgIdAttribute, orgId);
        processedClaimAttributes.put(orgNameAttribute, orgName);
        try {
            Map<String, UserStoreConfig> userStoreConfigs = organizationManager.getUserStoreConfigs(orgId);
            // DN is mandatory for organization. Hence cannot be null.
            String newUserDn = userStoreConfigs.get(DN).getValue();
            // Patch organization attributes of the user
            super.doSetUserAttributesWithID(userID, processedClaimAttributes, profileName);
            // Move user to a different OU
            //TODO this is to simply skip admin user's move during the  ROOT claim set. Fix this properly
            if (getAuthenticatedUsername() != null) {
                moveUser(userID, newUserDn);
            }
        } catch (OrganizationManagementException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_MOVING_LDAP_ENTRY;
            throw new UserStoreException(String.format(errorMessage.getMessage(), userID), errorMessage.getCode());
        }
    }

    @Override
    protected void persistUser(String userID, String userName, Object credential, String[] roleList,
            Map<String, String> claims) throws UserStoreException {

        // 'admin' user creation may trigger before the user store is fully activated.
        // Call super when such
        // Child classes who override this method must duplicate the below logic
        try {
            if (!OrganizationUserStoreDataHolder.getInstance().isActive()) {
                if (log.isDebugEnabled()) {
                    log.debug("Creating admin user : " + userName + " with super()");
                }
                super.persistUser(userID, userName, credential, roleList, claims);
                return;
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            ErrorMessage errorMessage = ERROR_PERSISTING_USER;
            String msg = String.format(errorMessage.getMessage(), userName);
            log.error(msg, e);
            throw new UserStoreException(msg, errorMessage.getCode(), e);
        }
        OrganizationManager organizationService = OrganizationUserStoreDataHolder.getInstance().getOrganizationService();
        String orgNameClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_NAME_CLAIM_URI)) ?
                IdentityUtil.getProperty(ORGANIZATION_NAME_CLAIM_URI).trim() :
                ORGANIZATION_NAME_DEFAULT_CLAIM_URI;
        String orgIdClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_ID_CLAIM_URI)) ?
                IdentityUtil.getProperty(ORGANIZATION_ID_CLAIM_URI).trim() :
                ORGANIZATION_ID_DEFAULT_CLAIM_URI;

        boolean nameAsIdentifier = false;
        String orgIdentifier;
        if (claims != null && !StringUtils.isBlank(claims.get(orgNameClaimUri))) {
            orgIdentifier = claims.get(orgNameClaimUri).trim();
            nameAsIdentifier = true;
        } else if (claims != null && !StringUtils.isBlank(claims.get(orgIdClaimUri))) {
            orgIdentifier = claims.get(orgIdClaimUri).trim();
        } else {
            // If org name or id is not defined in the request, user will be created under ROOT
            nameAsIdentifier = true;
            orgIdentifier = ROOT;
        }
        Organization organization;
        try {
            orgIdentifier = nameAsIdentifier ?
                    organizationService.getOrganizationIdByName(orgIdentifier): orgIdentifier;
            organization = organizationService.getOrganization(orgIdentifier, false);
            claims.put(orgNameClaimUri, organization.getName());
            claims.put(orgIdClaimUri, organization.getId());
        } catch (OrganizationManagementClientException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ORG_NOT_FOUND;
            String msg = String.format(errorMessage.getMessage(), orgIdentifier);
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, errorMessage.getCode(), e);
        } catch (OrganizationManagementException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_GETTING_ORG;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        }
        // Authorize user creation request
        if (!isAuthorized(claims.get(orgIdClaimUri), USER_MGT_CREATE_PERMISSION)) {
            throw new UserStoreException(ErrorMessage.ERROR_NOT_AUTHORIZED.getMessage(),
                    ErrorMessage.ERROR_NOT_AUTHORIZED.getCode());
        }
        // Check if organization is active
        if (!Organization.OrgStatus.ACTIVE.equals(organization.getStatus())) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ORG_NOT_ACTIVE;
            String errorMsg = String.format(errorMessage.getMessage(), orgIdentifier);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new UserStoreException(errorMsg, errorMessage.getCode());
        }
        String orgDn;
        try {
            // Get user store configs by organization ID
            orgDn = organizationService.getUserStoreConfigs(orgIdentifier).get(DN).getValue();
        } catch (OrganizationManagementException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_GETTING_ORG;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Organization id: " + orgIdentifier + ", DN: " + orgDn);
        }
        DirContext dirContext = getOrganizationDirectoryContext(orgDn);

        /* getting add user basic attributes */
        BasicAttributes basicAttributes = getAddUserBasicAttributes(userName);
        BasicAttribute userPassword = new BasicAttribute("userPassword");
        String passwordHashMethod = this.realmConfig.getUserStoreProperty(PASSWORD_HASH_METHOD);
        if (passwordHashMethod == null) {
            passwordHashMethod = realmConfig.getUserStoreProperty("passwordHashMethod");
        }
        byte[] passwordToStore = UserCoreUtil.getPasswordToStore(credential, passwordHashMethod, kdcEnabled);
        userPassword.add(passwordToStore);
        basicAttributes.put(userPassword);
        /* setting claims */
        setUserClaimsWithID(claims, basicAttributes, userID, userName);

        try {
            NameParser ldapParser = dirContext.getNameParser("");
            Name compoundName = ldapParser
                    .parse(realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE) + "="
                            + escapeSpecialCharactersForDN(userName));

            if (log.isDebugEnabled()) {
                log.debug("Binding user: " + compoundName);
            }
            dirContext.bind(compoundName, null, basicAttributes);
        } catch (NamingException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ACCESSING_DIR_CONTEXT;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage.getMessage(), e);
            }
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } finally {
            JNDIUtil.closeContext(dirContext);
            // Clearing password byte array
            UserCoreUtil.clearSensitiveBytes(passwordToStore);
        }

        if (roleList != null && roleList.length > 0) {
            try {
                // Update the user roles
                doUpdateRoleListOfUserWithID(userID, null, roleList);
                if (log.isDebugEnabled()) {
                    log.debug("Roles are added for user : " + userName + " successfully.");
                }
            } catch (UserStoreException e) {
                ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_ROLE_UPDATE;
                String errorMsg = String.format(errorMessage.getMessage(), userName);
                if (log.isDebugEnabled()) {
                    log.debug(errorMsg);
                }
                throw new UserStoreException(errorMsg, errorMessage.getCode(), e);
            }
        }
    }

    //***************** Start of newly introduced methods *****************

    protected void moveUser(String userID, String newDn) throws UserStoreException {

        // Get the LDAP Directory context.
        DirContext dirContext = this.connectionSource.getContext();
        String username = getUserNameFromUserID(userID);
        String currentDn = getNameInSpaceForUsernameFromLDAP(username);
        String prefix = StringUtils.contains(currentDn, ',') ? currentDn.substring(0, currentDn.indexOf(",")) : null;
        newDn = prefix != null ? prefix.concat(",").concat(newDn) : null;
        try {
            if (newDn != null || currentDn != null) {
                // Move user
                if (log.isDebugEnabled()) {
                    log.info("Moving user. Current DN : " + currentDn + ", new DN : " + newDn);
                }
                dirContext.rename(currentDn, newDn);
                // Update the user DN cache
                putToUserCache(username, new LdapName(newDn));
            } else {
                throw new UserStoreException(ErrorMessage.ERROR_RESOLVING_DN.getMessage(),
                        ErrorMessage.ERROR_RESOLVING_DN.getCode());
            }
        } catch (NamingException | UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_ORG_MOVE;
            String errorMsg = String.format(errorMessage.getMessage(), userID);
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new UserStoreException(errorMsg, errorMessage.getCode(), e);
        } finally {
            if (dirContext != null) {
                JNDIUtil.closeContext(dirContext);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void createOu(String dn, String rdn) throws UserStoreException {

        DirContext dirContext = null;
        try {
            dirContext = connectionSource.getContext();
            Attributes attributes = new BasicAttributes(true);
            Attribute objClass = new BasicAttribute("objectclass");
            objClass.add("top");
            objClass.add("organizationalUnit");
            attributes.put(objClass);
            // Replace RDN from the DN with a temporary place holder '#'
            dn = StringUtils.replaceOnce(dn, "=".concat(rdn), "#");
            // Sanitize RDN
            rdn = Utils.escapeSpecialCharacters(rdn);
            // Construct sanitized DN
            dn = StringUtils.replaceOnce(dn, "#", "=".concat(rdn));
            if (log.isDebugEnabled()) {
                log.debug("Creating the DN: " + dn);
            }
            dirContext.createSubcontext(dn, attributes);
            if (log.isDebugEnabled()) {
                log.debug("Successfully created the DN: " + dn);
            }
        } catch (UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ACCESSING_DIR_CONTEXT;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } catch (NamingException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_CREATING_DN;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } finally {
            if (dirContext != null) {
                JNDIUtil.closeContext(dirContext);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public void deleteOu(String dn) throws UserStoreException {

        DirContext dirContext = null;
        try {
            dirContext = connectionSource.getContext();
            dirContext.destroySubcontext(dn);
            if (log.isDebugEnabled()) {
                log.debug("Successfully destroyed the DN: " + dn);
            }
        } catch (UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ACCESSING_DIR_CONTEXT;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } catch (NamingException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_DELETING_DN;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } finally {
            if (dirContext != null) {
                JNDIUtil.closeContext(dirContext);
            }
        }
    }

    protected String getAuthorizedSearchFilter(String searchFilter, String orgIdentifierAttribute,
            boolean filterByOrgName) throws UserStoreException {

        OrganizationAuthorizationDao authorizationDao =
                OrganizationUserStoreDataHolder.getInstance().getOrganizationAuthDao();
        List<String> orgList;
        try {
            orgList = authorizationDao
                    .findAuthorizedOrganizationsList(getAuthenticatedUserId(), getTenantId(),
                            USER_MGT_LIST_PERMISSION, filterByOrgName);
            // If user doesn't have user list permission over any organization, do not change the filter
            // This is to cater JVM initiated user listing requests. Tomcat valve is throttling such SCIM requests.
            if (orgList.isEmpty()) {
                return searchFilter;
            }
        } catch (OrganizationManagementException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_GETTING_AUTHORIZED_ORG;
            String errorMsg = String.format(errorMessage.getMessage(), USER_MGT_LIST_PERMISSION);
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, errorMessage.getCode(), e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_GETTING_AUTHENTICATED_USER;
            String errorMsg = String.format(errorMessage.getMessage(), getAuthenticatedUsername());
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, errorMessage.getCode(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Initial search filter: " + searchFilter);
        }
        StringJoiner joiner = new StringJoiner(")(","(", ")");
        orgList.forEach(org -> joiner.add(orgIdentifierAttribute + "=" + org));
        String orgFilter = "(|#)".replace("#", joiner.toString());
        // Initial filter: (&(objectClass=person)(homeEmail=nipunt@wso2.com))
        // org filter :
        // (|(organization=89651ae3-83fd-43eb-8fd4-7528ef69e3bd)(organization=bc26d67e-a6e1-4c16-800e-9594c08cccf5))
        // Final search filter :
        // (&(objectClass=person)(homeEmail=nipunt@wso2.com)(|(organization=89651ae3-83fd-43eb-8fd4-7528ef69e3bd)
        // (organization=bc26d67e-a6e1-4c16-800e-9594c08cccf5)))
        return searchFilter.substring(0, searchFilter.lastIndexOf(")")).concat(orgFilter).concat(")");
    }

    protected DirContext getOrganizationDirectoryContext(String dn) throws UserStoreException {

        DirContext mainDirContext = this.connectionSource.getContext();
        try {
            return (DirContext) mainDirContext.lookup(escapeDNForSearch(dn));
        } catch (NamingException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_ACCESSING_DIR_CONTEXT;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage.getMessage(), e);
            }
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } finally {
            JNDIUtil.closeContext(mainDirContext);
        }
    }

    protected boolean isAuthorizedAsAdmin() throws UserStoreException {

        // Having this permission ('/permission/admin/manage/identity/organizationmgt/admin') assigned from the WSO2
        // default registry based permission model allows:  listing all the organizations, listing all the users,
        // listing all the groups and granting any permission to any user against any organization.
        try {
            AuthorizationManager authorizationManager = OrganizationUserStoreDataHolder.getInstance().
                    getRealmService().getTenantUserRealm(getTenantId()).getAuthorizationManager();
            return authorizationManager.isUserAuthorized(getAuthenticatedUsername(), ORGANIZATION_ADMIN_PERMISSION, UI_EXECUTE);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_CHECKING_FOR_ADMIN;
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        }
    }

    protected boolean isAuthorized(String organizationId, String permission)
            throws org.wso2.carbon.user.core.UserStoreException {

        // To create a user inside an organization
        // you should have '/permission/admin/organizations/create' over the subject organization
        OrganizationAuthorizationDao authorizationDao =
                OrganizationUserStoreDataHolder.getInstance().getOrganizationAuthDao();
        try {
            return authorizationDao.isUserAuthorized(getAuthenticatedUserId(), organizationId, permission);
        } catch (OrganizationManagementException | org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg =
                    "Error while authorizing the action: " + permission + ", organization id: " + organizationId;
            log.error(errorMsg, e);
            throw new org.wso2.carbon.user.core.UserStoreException(errorMsg, e);
        }
    }

    private String getAuthenticatedUserId() throws org.wso2.carbon.user.api.UserStoreException {

        return getUserIDFromUserName(getAuthenticatedUsername(), getTenantId());
    }

    protected String getAuthenticatedUsername() {

        //TODO check for authentication requests ?
        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    private String getUserIDFromUserName(String username, int tenantId) throws
            org.wso2.carbon.user.api.UserStoreException {

        if (username == null) {
            return null;
        }
        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) OrganizationUserStoreDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            return userStoreManager.getUserIDFromUserName(username);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error obtaining ID for the username: " + username + ", tenant id: " + tenantId;
            throw new org.wso2.carbon.user.api.UserStoreException(errorMsg, e);
        }
    }

    //***************** End of newly introduced methods *********************************

    //***************** Start of duplicated and altered private methods *****************

    private List<User> performLDAPSearch(LdapContext ldapContext, LDAPSearchSpecification ldapSearchSpecification,
            String orgSearchBase, String orgIdentifierAttribute, int pageSize, int offset,
            List<ExpressionCondition> expressionConditions, boolean filterByOrgName)
            throws UserStoreException {

        byte[] cookie;
        int pageIndex = -1;
        boolean isGroupFiltering = ldapSearchSpecification.isGroupFiltering();
        boolean isUsernameFiltering = ldapSearchSpecification.isUsernameFiltering();
        boolean isClaimFiltering = ldapSearchSpecification.isClaimFiltering();
        boolean isMemberShipPropertyFound = ldapSearchSpecification.isMemberShipPropertyFound();

        String searchFilter = ldapSearchSpecification.getSearchFilterQuery();
        SearchControls searchControls = ldapSearchSpecification.getSearchControls();
        String[] searchBaseArray;
        // If organization is defined in the request
        if (orgSearchBase != null) {
            // Search only in the given OU, not in sub trees
            searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
            // Search in the organization's user search base (DN)
            searchBaseArray = new String[] { orgSearchBase };
        } else {
            // admin users can do full tree search
            // Non-admin users can only search in allowed organizations
            // Threads without an authenticated user, are also eligible for a full tree search
            if (StringUtils.isNotBlank(getAuthenticatedUsername()) && !isAuthorizedAsAdmin()) {
                // Alter the search filter to include authorized org IDs as search conditions
                searchFilter = getAuthorizedSearchFilter(searchFilter, orgIdentifierAttribute, filterByOrgName);
            }
            // Use the default search base (Search will NOT be limited to one level)
            searchBaseArray = ldapSearchSpecification.getSearchBases().split("#");
        }

        if (log.isDebugEnabled()) {
            log.debug("Searching in the subdirectory: " + Arrays.toString(searchBaseArray));
        }
        List<String> returnedAttributes = Arrays.asList(searchControls.getReturningAttributes());
        NamingEnumeration<SearchResult> answer = null;
        List<User> users = new ArrayList<>();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Searching for user(s) with SearchFilter: %s and page size %d", searchFilter,
                    pageSize));
        }
        try {
            for (String searchBase: searchBaseArray) {
                do {
                    List<User> tempUserList = new ArrayList<>();
                    answer = ldapContext.search(escapeDNForSearch(searchBase), searchFilter, searchControls);
                    if (answer.hasMore()) {
                        tempUserList = getUserListFromSearch(isGroupFiltering, returnedAttributes, answer,
                                isSingleAttributeFilterOperation(expressionConditions));
                        pageIndex++;
                    }
                    if (CollectionUtils.isNotEmpty(tempUserList)) {
                        if (isMemberShipPropertyFound) {
                            /*
                            Pagination is not supported for 'member' attribute group filtering. Also,
                            we need do post-processing if we found username filtering or claim filtering,
                            because can't apply claim filtering with memberShip group filtering and
                            can't apply username filtering with 'CO', 'EW' filter operations.
                             */
                            users = membershipGroupFilterPostProcessing(isUsernameFiltering, isClaimFiltering,
                                    expressionConditions, tempUserList);
                            break;
                        } else {
                            // Handle pagination depends on given offset, i.e. start index.
                            generatePaginatedUserList(pageIndex, offset, pageSize, tempUserList, users);
                            int needMore = pageSize - users.size();
                            if (needMore == 0) {
                                break;
                            }
                        }
                    }
                    cookie = parseControls(ldapContext.getResponseControls());
                    String userNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
                    ldapContext.setRequestControls(new Control[] {
                            new PagedResultsControl(pageSize, cookie, Control.CRITICAL),
                            new SortControl(userNameAttribute, Control.NONCRITICAL)
                    });
                } while ((cookie != null) && (cookie.length != 0));
            }
        } catch (PartialResultException e) {
            // Can be due to referrals in AD. So just ignore error.
            if (isIgnorePartialResultException()) {
                if (log.isDebugEnabled()) {
                    log.debug(String.format("Error occurred while searching for user(s) for filter: %s",
                            searchFilter), e);
                }
            } else {
                ErrorMessage errorMessage = ErrorMessage.ERROR_SEARCHING_WITH_FILTER;
                String msg = String.format(errorMessage.getMessage(), searchFilter);
                log.error(msg, e);
                throw new UserStoreException(msg, errorMessage.getCode(), e);
            }
        } catch (NamingException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_SEARCHING_WITH_FILTER;
            String msg = String.format(errorMessage.getMessage(), searchFilter);
            log.error(msg, e);
            throw new UserStoreException(msg, errorMessage.getCode(), e);
        } catch (IOException e) {
            ErrorMessage errorMessage = ErrorMessage.ERROR_WHILE_PAGINATED_SEARCH;
            log.error(errorMessage.getMessage(), e);
            throw new UserStoreException(errorMessage.getMessage(), errorMessage.getCode(), e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
        }
        return users;
    }

    private String getUserIDFromProperty(String property, String claimValue) throws UserStoreException {

        try {
            // Call super method to avoid recursive loop
            List<String> userIds = super.doGetUserListFromPropertiesWithID(property, claimValue, null);
            if (userIds.isEmpty()) {
                if (log.isDebugEnabled()) {
                    log.debug(
                            "No UserID found for the property: " + property + ", value: " + claimValue + ", in domain:"
                                    + " " + getMyDomainName());
                }
                return null;
            } else if (userIds.size() > 1) {
                throw new UserStoreException(
                        "Invalid scenario. Multiple users cannot be found for the given value: " + claimValue
                                + "of the " + "property: " + property);
            } else {
                // username can have only one userId. Take the first element.
                return userIds.get(0);
            }
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            throw new UserStoreException(
                    "Error occurred while retrieving the userId of domain : " + getMyDomainName() + " and " + "property"
                            + property + " value: " + claimValue, e);
        }
    }

    //**************** End of duplicated and altered private methods ****************

    //********************* Start of duplicated private methods *********************

    protected String escapeSpecialCharactersForDN(String text) {

        boolean replaceEscapeCharacters = true;
        String replaceEscapeCharactersAtUserLoginString = realmConfig
                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_REPLACE_ESCAPE_CHARACTERS_AT_USER_LOGIN);

        if (replaceEscapeCharactersAtUserLoginString != null) {
            replaceEscapeCharacters = Boolean.parseBoolean(replaceEscapeCharactersAtUserLoginString);
            if (log.isDebugEnabled()) {
                log.debug("Replace escape characters configured to: " + replaceEscapeCharactersAtUserLoginString);
            }
        }

        if (replaceEscapeCharacters) {
            StringBuilder sb = new StringBuilder();
            if ((text.length() > 0) && ((text.charAt(0) == ' ') || (text.charAt(0) == '#'))) {
                sb.append('\\'); // add the leading backslash if needed
            }
            for (int i = 0; i < text.length(); i++) {
                char currentChar = text.charAt(i);
                switch (currentChar) {
                case '\\':
                    if (text.charAt(i + 1) == '*') {
                        sb.append("*");
                        i++;
                        break;
                    }
                    sb.append("\\\\");
                    break;
                case ',':
                    sb.append("\\,");
                    break;
                case '+':
                    sb.append("\\+");
                    break;
                case '"':
                    sb.append("\\\"");
                    break;
                case '<':
                    sb.append("\\<");
                    break;
                case '>':
                    sb.append("\\>");
                    break;
                case ';':
                    sb.append("\\;");
                    break;
                default:
                    sb.append(currentChar);
                }
            }
            if ((text.length() > 1) && (text.charAt(text.length() - 1) == ' ')) {
                sb.insert(sb.length() - 1, '\\'); // add the trailing backslash if needed
            }
            if (log.isDebugEnabled()) {
                log.debug("value after escaping special characters in " + text + ": " + sb.toString());
            }
            return sb.toString();
        } else {
            return text;
        }
    }

    /**
     * Get user list from multi attribute search filter.
     *
     * @param isGroupFiltering        Whether the filtering has the group attribute name.
     * @param returnedAttributes      Returned Attributes.
     * @param answer                  Answer.
     * @param isSingleAttributeFilter Whether the original request is from a single attribute filter or a multi
     *                                attribute filter, so that AND operation can be omitted during the filtering
     *                                process.
     * @return A users list.
     * @throws UserStoreException
     * @throws NamingException
     */
    protected List<User> getUserListFromSearch(boolean isGroupFiltering, List<String> returnedAttributes,
                                             NamingEnumeration<SearchResult> answer, boolean isSingleAttributeFilter)
            throws UserStoreException {

        List<User> tempUsersList;
        if (isGroupFiltering) {
            if (returnedAttributes.contains(realmConfig.getUserStoreProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE))) {
                tempUsersList = getUserListFromMembershipGroupFilterResult
                        (answer, returnedAttributes, isSingleAttributeFilter);
            }
            else {
                tempUsersList = getUserListFromMemberOfGroupFilterResult(answer);
            }
        } else {
            tempUsersList = getUserListFromNonGroupFilterResult(answer, returnedAttributes);
        }
        return tempUsersList;
    }

    protected List<User> membershipGroupFilterPostProcessing(boolean isUsernameFiltering, boolean isClaimFiltering,
            List<ExpressionCondition> expressionConditions, List<User> tempUserList) throws UserStoreException {

        List<User> users;
        if (isUsernameFiltering) {
            tempUserList = getMatchUsersFromMemberList(expressionConditions, tempUserList);
        }

        if (isClaimFiltering) {
            users = getUserListFromClaimFiltering(expressionConditions, tempUserList);
        } else {
            users = tempUserList;
        }
        return users;
    }

    /**
     * Parse the search result of non group filtering and get the user list.
     *
     * @param answer                Answer from LDAP search.
     * @param returnedAttributes    Returned attributes.
     * @return  A users list.
     * @throws UserStoreException
     */
    private List<User> getUserListFromNonGroupFilterResult(NamingEnumeration<SearchResult> answer,
                                                           List<String> returnedAttributes)
            throws UserStoreException {

        List<User> finalUserList = new ArrayList<>();
        String userAttributeSeparator = ",";
        NamingEnumeration<?> attrs = null;

        try {
            while (answer.hasMoreElements()) {
                SearchResult searchResult = answer.next();
                Attributes attributes = searchResult.getAttributes();
                if (attributes == null) {
                    continue;
                }
                Attribute attribute = attributes.get(returnedAttributes.get(0));
                if (attribute == null) {
                    continue;
                }
                StringBuffer attrBuffer = new StringBuffer();
                for (attrs = attribute.getAll(); attrs.hasMore(); ) {
                    String attr = (String) attrs.next();
                    if (StringUtils.isNotEmpty(attr.trim())) {
                        String attrSeparator = realmConfig.getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
                        if (StringUtils.isNotEmpty(attrSeparator.trim())) {
                            userAttributeSeparator = attrSeparator;
                        }
                        attrBuffer.append(attr + userAttributeSeparator);
                        if (log.isDebugEnabled()) {
                            log.debug(returnedAttributes.get(0) + " : " + attr);
                        }
                    }
                }
                String userNamePropertyValue = attrBuffer.toString();
                Attribute serviceNameObject = attributes.get(returnedAttributes.get(1));
                String serviceNameAttributeValue = null;
                if (serviceNameObject != null) {
                    serviceNameAttributeValue = (String) serviceNameObject.get();
                }
                /* Length needs to be more than userAttributeSeparator.length() for a valid attribute,
                since we attach userAttributeSeparator. */
                if (userNamePropertyValue.trim().length() > userAttributeSeparator.length()) {
                    if (LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE.equals(serviceNameAttributeValue)) {
                        continue;
                    }
                    userNamePropertyValue = userNamePropertyValue.substring(0, userNamePropertyValue.length() -
                            userAttributeSeparator.length());

                    Attribute userIdObject =
                            attributes.get(realmConfig.getUserStoreProperty(LDAPConstants.USER_ID_ATTRIBUTE));
                    String userIdAttributeValue = null;
                    if (userIdObject != null) {
                        userIdAttributeValue = resolveLdapAttributeValue(userIdObject.get());
                    }

                    String domain = this.getRealmConfiguration()
                            .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);

                    User user = getUser(userIdAttributeValue, userNamePropertyValue);
                    user.setDisplayName(null);
                    user.setUserStoreDomain(domain);
                    user.setTenantDomain(getTenantDomain(tenantId));
                    finalUserList.add(user);
                }
            }
        } catch (NamingException e) {
            log.error(String.format("Error occurred while getting user list from non group filter %s", e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            // Close the naming enumeration and free up resources
            JNDIUtil.closeNamingEnumeration(attrs);
        }
        return finalUserList;
    }

    /**
     * Parse the search result of group filtering and get the user list.
     * As it's membership group filtering, we retrieve all members of the requested group(s) and then
     * get the mutual members' out of it as a DN list.
     *
     * @param answer                  Answer.
     * @param returnedAttributes      Returned Attributes.
     * @param isSingleAttributeFilter Whether the original request is from a single attribute filter or a multi
     *                                attribute filter, so that AND operation can be omitted during the filtering
     *                                process.
     * @return A users list.
     * @throws UserStoreException
     */
    private List<User> getUserListFromMembershipGroupFilterResult(NamingEnumeration<SearchResult> answer,
                                                                  List<String> returnedAttributes, boolean
                                                                          isSingleAttributeFilter) throws UserStoreException {

        // User DN list.
        List<String> userListFromSearch = new ArrayList<>();
        // Multi group retrieval.
        int count = 0;
        NamingEnumeration<?> attrs = null;
        List<User> finalUserList;

        try {
            while (answer.hasMoreElements()) {
                count++;
                List<String> tempUserList = new ArrayList<>();
                SearchResult searchResult = answer.next();
                Attributes attributes = searchResult.getAttributes();
                if (attributes == null)
                    continue;
                NamingEnumeration attributeEntry;
                for (attributeEntry = attributes.getAll(); attributeEntry.hasMore(); ) {
                    Attribute valAttribute = (Attribute) attributeEntry.next();
                    if (isAttributeEqualsProperty(returnedAttributes.get(0), valAttribute.getID())) {
                        NamingEnumeration values;
                        for (values = valAttribute.getAll(); values.hasMore(); ) {
                            tempUserList.add(values.next().toString());
                        }
                    }
                }
                /*
                 When singleAttributeFilter is true, that implies that the request is a single attribute filter. In
                 this case, the intersection (AND operation) should not be performed on the filtered results.
                 Following IF block handles the single attribute filter.
                 */
                if (isSingleAttributeFilter) {
                    userListFromSearch.addAll(tempUserList);
                } else {
                    if (count == 1) {
                        userListFromSearch.addAll(tempUserList);
                    } else {
                        userListFromSearch.retainAll(tempUserList);
                    }
                }
            }
        } catch (NamingException e) {
            log.error(String.format("Error occurred while getting user list from group filter %s", e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            JNDIUtil.closeNamingEnumeration(attrs);
        }

        // We need iterate over users' DN list and get users.
        finalUserList = getUserListFromDNList(userListFromSearch);
        return finalUserList;
    }

    /**
     * Parse the search result of group filtering and get the user list.
     * As it's memberOf group filtering, directly get the user name list from search result.
     *
     * @param answer        LDAP search answer.
     * @return A users list.
     * @throws UserStoreException
     */
    private List<User> getUserListFromMemberOfGroupFilterResult(NamingEnumeration<SearchResult> answer)
            throws UserStoreException {

        List<User> finalUserList = new ArrayList<>();
        try {
            while (answer.hasMoreElements()) {
                SearchResult searchResult = answer.next();
                if (searchResult.getAttributes() != null) {
                    Attribute userName = searchResult.getAttributes().
                            get(realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE));
                    Attribute userID = searchResult.getAttributes().
                            get(realmConfig.getUserStoreProperty(LDAPConstants.USER_ID_ATTRIBUTE));
                    /*
                     * If this is a service principle, just ignore and
                     * iterate rest of the array. The entity is a service if
                     * value of surname is Service.
                     */
                    String serviceNameAttribute = "sn";
                    Attribute attrSurname = searchResult.getAttributes().get(serviceNameAttribute);

                    if (attrSurname != null) {
                        if (log.isDebugEnabled()) {
                            log.debug(serviceNameAttribute + " : " + attrSurname);
                        }
                        String serviceName = (String) attrSurname.get();
                        if (serviceName != null && serviceName
                                .equals(LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE)) {
                            continue;
                        }
                    }
                    String name = null;
                    String displayName = null;
                    String id = null;
                    String domain = null;
                    if (userName != null) {
                        name = resolveLdapAttributeValue(userName.get());
                        domain = this.getRealmConfiguration()
                                .getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                    }
                    if (userID != null) {
                        id = resolveLdapAttributeValue(userID.get());
                    }
                    User user = getUser(id, name);
                    user.setDisplayName(displayName);
                    user.setUserStoreDomain(domain);
                    user.setTenantDomain(getTenantDomain(tenantId));
                    finalUserList.add(user);
                }
            }
        } catch (NamingException e) {
            log.error(String.format("Error occurred while getting user list from non group filter %s", e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        }
        return finalUserList;
    }

    /**
     * Get user name list from DN list.
     *
     * @param userListFromSearch    User DN list obtained from search.
     * @return List of user objects.
     * @throws UserStoreException
     */
    private List<User> getUserListFromDNList(List<String> userListFromSearch) throws UserStoreException {

        List<User> usersList = new ArrayList<>();
        DirContext dirContext = this.connectionSource.getContext();
        String userNameProperty = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        String displayNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
        String userIdProperty = realmConfig.getUserStoreProperty(LDAPConstants.USER_ID_ATTRIBUTE);
        String[] requiredAttributes = {userNameProperty, displayNameAttribute, userIdProperty};

        for (String userFromSearch : userListFromSearch) {
            try {
                String displayName = null;
                String userName = null;
                String userId = null;
                Attributes userAttributes = dirContext.getAttributes
                        (escapeDNForSearch(userFromSearch), requiredAttributes);

                if (userAttributes != null) {
                    Attribute userNameAttribute = userAttributes.get(userNameProperty);
                    if (userNameAttribute != null) {
                        userName = (String) userNameAttribute.get();
                    }
                    if (StringUtils.isNotEmpty(displayNameAttribute)) {
                        Attribute displayAttribute = userAttributes.get(displayNameAttribute);
                        if (displayAttribute != null) {
                            displayName = (String) displayAttribute.get();
                        }
                    }
                    Attribute userIdAttribute = userAttributes.get(userIdProperty);
                    if (userIdAttribute != null) {
                        userId = resolveLdapAttributeValue(userIdAttribute.get());
                    }
                }
                String domainName =
                        realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME);
                /* Username will be null in the special case where the username attribute has changed to another
                and having different userNameProperty than the current user-mgt.xml. */
                if (userName != null) {
                    User user = getUser(userId, userName);
                    user.setDisplayName(displayName);
                    user.setUserStoreDomain(domainName);
                    user.setTenantDomain(getTenantDomain(tenantId));
                    usersList.add(user);
                } else {
                    // Skip listing users which are not applicable to current user-mgt.xml
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("User %s doesn't have the user name property %s", userFromSearch,
                                userNameProperty));
                    }
                }
            } catch (NamingException e) {
                log.error(String.format("Error in reading user information in the user store for the user %s, %s",
                        userFromSearch, e.getMessage()));
                throw new UserStoreException(e.getMessage(), e);
            }
        }
        return usersList;
    }

    /**
     * Post processing the user list, when found membership group filter with user name filtering.
     * Get match users from member list. When found username filtering.
     *
     * @param expressionConditions  Expression conditions.
     * @param userList              List of users to be filtered.
     * @return Filtered user list.
     */
    private List<User> getMatchUsersFromMemberList(List<ExpressionCondition> expressionConditions,
                                                   List<User> userList) {
        /*
        If group filtering and username filtering found, we need to get match users names only.
        'member' filtering retrieve all the members once the conditions matched because 'member' is a
        multi valued attribute.
        */
        List<User> derivedUserList = new ArrayList<>();

        for (ExpressionCondition expressionCondition : expressionConditions) {
            if (ExpressionAttribute.USERNAME.toString().equals(expressionCondition.getAttributeName())) {
                derivedUserList.addAll(getMatchUsers(expressionCondition, userList));
            }
        }
        LinkedHashSet<User> linkedHashSet = new LinkedHashSet<>();
        linkedHashSet.addAll(derivedUserList);
        derivedUserList.clear();
        derivedUserList.addAll(linkedHashSet);
        return derivedUserList;
    }

    /**
     * Get match users from given expression condition.
     *
     * @param expressionCondition   Expression condition.
     * @param users List of users to be filtered.
     * @return Filtered user list.
     */
    private List<User> getMatchUsers(ExpressionCondition expressionCondition, List<User> users) {

        List<User> newUsersList = new ArrayList<>();
        for (User user : users) {
            if (ExpressionOperation.SW.toString().equals(expressionCondition.getOperation())
                    && user.getUsername().startsWith(expressionCondition.getAttributeValue()) && !newUsersList.contains(user)) {
                newUsersList.add(user);
            } else if (ExpressionOperation.EQ.toString().equals(expressionCondition.getOperation())
                    && user.getUsername().equals(expressionCondition.getAttributeValue()) && !newUsersList.contains(user)) {
                newUsersList.add(user);
            } else if (ExpressionOperation.CO.toString().equals(expressionCondition.getOperation())
                    && user.getUsername().contains(expressionCondition.getAttributeValue()) && !newUsersList.contains(user)) {
                newUsersList.add(user);
            } else if (ExpressionOperation.EW.toString().equals(expressionCondition.getOperation())
                    && user.getUsername().endsWith(expressionCondition.getAttributeValue()) && !newUsersList.contains(user)) {
                newUsersList.add(user);
            }
        }
        return newUsersList;
    }

    /**
     * Post processing the user list, when membership group filter with claim filtering is found.
     *
     * @param expressionConditions  Expression conditions.
     * @param tempUserList          User list to be filtered.
     * @return Filtered user list.
     * @throws UserStoreException
     */
    private List<User> getUserListFromClaimFiltering(List<ExpressionCondition> expressionConditions,
                                                     List<User> tempUserList) throws UserStoreException {

        List<User> claimSearchUserList = new ArrayList<>();
        List<ExpressionCondition> derivedConditionList = expressionConditions;
        Iterator<ExpressionCondition> iterator = derivedConditionList.iterator();

        while (iterator.hasNext()) {
            ExpressionCondition expressionCondition = iterator.next();
            if (ExpressionAttribute.ROLE.toString().equals(expressionCondition.getAttributeName())) {
                iterator.remove();
            }
        }
        LDAPSearchSpecification claimSearch = new LDAPSearchSpecification(realmConfig, derivedConditionList);
        SearchControls claimSearchControls = claimSearch.getSearchControls();
        DirContext claimSearchDirContext = this.connectionSource.getContext();
        NamingEnumeration<SearchResult> tempAnswer = null;
        try {
            tempAnswer = claimSearchDirContext.search(claimSearch.getSearchBases(),
                    claimSearch.getSearchFilterQuery(), claimSearchControls);
            if (tempAnswer.hasMore()) {
                claimSearchUserList = getUserListFromNonGroupFilterResult(tempAnswer,
                        Arrays.asList(claimSearchControls.getReturningAttributes()));
            }
        } catch (NamingException e) {
            log.error(String.format("Error occurred while doing claim filtering for user(s) with filter: %s, %s",
                    claimSearch.getSearchFilterQuery(), e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            JNDIUtil.closeContext(claimSearchDirContext);
            JNDIUtil.closeNamingEnumeration(tempAnswer);
        }
        tempUserList.retainAll(claimSearchUserList);
        return tempUserList;
    }

    protected boolean isIgnorePartialResultException() {

        if (PROPERTY_REFERRAL_IGNORE.equals(realmConfig.getUserStoreProperty(LDAPConstants.PROPERTY_REFERRAL))) {
            return true;
        }
        return false;
    }

    private boolean isAttributeEqualsProperty(String property, String attribute) {

        if (StringUtils.isEmpty(property) || StringUtils.isEmpty(attribute)) {
            return false;
        }
        return property.equals(attribute) || property.equals(attribute.substring(0, attribute.indexOf(";")));
    }
    //********************* End of duplicated private methods *********************
}
