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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.custom.userstore.manager.internal.CustomUserStoreDataHolder;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.organization.mgt.core.OrganizationManager;
import org.wso2.carbon.identity.organization.mgt.core.dao.OrganizationAuthorizationDao;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementClientException;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.mgt.core.model.Organization;
import org.wso2.carbon.identity.organization.mgt.core.model.UserStoreConfig;
import org.wso2.carbon.identity.organization.mgt.core.usermgt.AbstractOrganizationMgtUserStoreManager;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;
import org.wso2.carbon.user.core.common.PaginatedSearchResult;
import org.wso2.carbon.user.core.common.UniqueIDPaginatedSearchResult;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.ldap.LDAPConstants;
import org.wso2.carbon.user.core.ldap.LDAPSearchSpecification;
import org.wso2.carbon.user.core.model.Condition;
import org.wso2.carbon.user.core.model.ExpressionAttribute;
import org.wso2.carbon.user.core.model.ExpressionCondition;
import org.wso2.carbon.user.core.model.ExpressionOperation;
import org.wso2.carbon.user.core.model.OperationalCondition;
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
import javax.naming.ldap.PagedResultsControl;
import javax.naming.ldap.PagedResultsResponseControl;
import javax.naming.ldap.SortControl;

import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_ID_CLAIM_URI;
import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_ID_DEFAULT_CLAIM_URI;
import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_NAME_CLAIM_URI;
import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_NAME_DEFAULT_CLAIM_URI;
import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_USER_CREATE_PERMISSION;
import static org.wso2.carbon.custom.userstore.manager.Constants.ROOT_ORG_NAME;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.DN;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.USER_MGT_CREATE_PERMISSION;
import static org.wso2.carbon.user.core.UserCoreConstants.RealmConfig.PROPERTY_DOMAIN_NAME;

public class CustomUserStoreManager extends AbstractOrganizationMgtUserStoreManager {

    private static final Log log = LogFactory.getLog(CustomUserStoreManager.class);

    private static final String PROPERTY_REFERRAL_IGNORE = "ignore";
    private static final String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";

    public CustomUserStoreManager() {
    }

    public CustomUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
            ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {

        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
    }

    public CustomUserStoreManager(RealmConfiguration realmConfig, ClaimManager claimManager,
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

        PaginatedSearchResult userNames = doGetUserList(condition, profileName, limit, offset, sortBy, sortOrder);
        UniqueIDPaginatedSearchResult userList = new UniqueIDPaginatedSearchResult();
        userList.setPaginatedSearchResult(userNames);
        userList.setSkippedUserCount(userNames.getSkippedUserCount());
        List<User> users = new ArrayList<>();
        for (String userName : userNames.getUsers()) {
            User user = getUser(null, userName);
            users.add(user);
        }
        userList.setUsers(users);
        return userList;
    }

    @Override
    protected PaginatedSearchResult doGetUserList(Condition condition, String profileName, int limit, int offset,
            String sortBy, String sortOrder) throws UserStoreException {

        PaginatedSearchResult result = new PaginatedSearchResult();
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
            org.wso2.carbon.user.api.UserRealm tenantUserRealm = CustomUserStoreDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(tenantId);
            org.wso2.carbon.user.api.ClaimManager claimManager = tenantUserRealm.getClaimManager();
            orgNameAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgNameClaimUri);
            orgIdAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgIdClaimUri);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error obtaining organization claim/attribute mappings : " + e.getMessage();
            log.error(errorMsg);
            throw new UserStoreException(errorMsg, e);
        }

        String orgSearchBase;
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
        // If organization is not defined in the request, assume root
        if (orgIdentifier == null) {
            orgIdentifier = ROOT_ORG_NAME;
            nameAsIdentifier = true;
        }
        // Resolve organization identifier
        OrganizationManager orgService = CustomUserStoreDataHolder.getInstance().getOrganizationService();
        try {
            orgIdentifier = nameAsIdentifier ? orgService.getOrganizationIdByName(orgIdentifier) : orgIdentifier;
        } catch (OrganizationManagementClientException e) {
            String errorMsg = "Failed resolving organization name : " + orgIdentifier + " to an organization id";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new UserStoreException(errorMsg, e);
        } catch (OrganizationManagementException e) {
            String errorMsg = "Error while obtaining organization Id : " + e.getMessage();
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, e);
        }
        // Resolve user search base
        try {
            // Get user store configs by organization ID
            orgSearchBase = orgService.getUserStoreConfigs(orgIdentifier).get(DN).getValue();
        } catch (OrganizationManagementException e) {
            String errorMsg = "Error while obtaining organization metadata : " + e.getMessage();
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, e);
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
        List<String> users;
        List<String> ldapUsers = new ArrayList<>();
        String userNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        try {
            ldapContext.setRequestControls(new Control[] {
                    new PagedResultsControl(pageSize, Control.CRITICAL),
                    new SortControl(userNameAttribute, Control.NONCRITICAL)
            });
            users = performLDAPSearch(ldapContext, ldapSearchSpecification, orgSearchBase, pageSize, offset,
                    expressionConditions);
            for (String ldapUser : users) {
                ldapUsers.add(UserCoreUtil.addDomainToName(ldapUser, getMyDomainName()));
            }
            result.setUsers(ldapUsers.toArray(new String[0]));
            return result;
        } catch (NamingException e) {
            log.error(String.format("Error occurred while performing paginated search, %s", e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } catch (IOException e) {
            log.error(String.format("Error occurred while setting paged results controls for paginated search, %s",
                    e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            JNDIUtil.closeContext(dirContext);
            JNDIUtil.closeContext(ldapContext);
        }
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
            org.wso2.carbon.user.api.UserRealm tenantUserRealm = CustomUserStoreDataHolder.getInstance()
                    .getRealmService().getTenantUserRealm(tenantId);
            org.wso2.carbon.user.api.ClaimManager claimManager = tenantUserRealm.getClaimManager();
            orgNameAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgNameClaimUri);
            orgIdAttribute = claimManager
                    .getAttributeName(this.realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME), orgIdClaimUri);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error obtaining organization claim/attribute mappings : " + e.getMessage();
            log.error(errorMsg);
            throw new UserStoreException(errorMsg, e);
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
        OrganizationManager organizationManager = CustomUserStoreDataHolder.getInstance().getOrganizationService();
        Organization organization;
        try {
            // Get organization id
            orgId = patchByName ? organizationManager.getOrganizationIdByName(orgIdentifier) : orgIdentifier;
            organization = organizationManager.getOrganization(orgId, false);
        } catch (OrganizationManagementException e) {
            throw new UserStoreException("Error while obtaining organization details.", e);
        }
        // Permission check for the new organization
        if (!isAuthorized(organization.getId(), USER_MGT_CREATE_PERMISSION)) {
            throw new UserStoreException("Forbidden organization : " + organization.getId());
        }
        // Set user claims to be patched
        orgName = patchById ? organization.getName() : orgIdentifier;
        processedClaimAttributes.put(orgIdAttribute, orgId);
        processedClaimAttributes.put(orgNameAttribute, orgName);
        try {
            Map<String, UserStoreConfig> userStoreConfigs = organizationManager.getUserStoreConfigs(orgId);
            // DN is mandatory for organization. Hence cannot be null.
            String newUserDn = userStoreConfigs.get(DN).getValue();
            // Patch organization attributes of the user
            super.doSetUserAttributesWithID(userID, processedClaimAttributes, profileName);
            // Move user to a different OU
            moveUser(userID, newUserDn);
        } catch (OrganizationManagementException e) {
            throw new UserStoreException("Error while moving the LDAP entry. user id : " + userID);
        }
    }

    private void moveUser(String userID, String newDn) throws UserStoreException {

        // Get the LDAP Directory context.
        DirContext dirContext = this.connectionSource.getContext();
        // Search the relevant user entry by user name.
        String userSearchBase = realmConfig.getUserStoreProperty(LDAPConstants.USER_SEARCH_BASE);
        String userSearchFilter = realmConfig.getUserStoreProperty(LDAPConstants.USER_ID_SEARCH_FILTER);
        String userIDAttribute = realmConfig.getUserStoreProperty(LDAPConstants.USER_ID_ATTRIBUTE);

        userSearchFilter = userSearchFilter.replace(LDAPConstants.UID, userIDAttribute);

        if (OBJECT_GUID.equalsIgnoreCase(userIDAttribute) && isBinaryUserAttribute(userIDAttribute)) {
            userID = transformUUIDToObjectGUID(userID);
            userSearchFilter = userSearchFilter.replace("?", userID);
        } else {
            userSearchFilter = userSearchFilter.replace("?", escapeSpecialCharactersForFilter(userID));
        }

        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        searchControls.setReturningAttributes(null);

        NamingEnumeration<SearchResult> returnedResultList = null;
        try {
            returnedResultList = dirContext.search(escapeDNForSearch(userSearchBase), userSearchFilter, searchControls);
            String oldDn = null;
            String prefix;
            // Assume only one user is returned from the search.
            if (returnedResultList.hasMore()) {
                oldDn = returnedResultList.next().getNameInNamespace();
                prefix = StringUtils.contains(oldDn, ',') ? oldDn.substring( 0, oldDn.indexOf(",")) : null;
                newDn = prefix != null ? prefix.concat(",").concat(newDn) : null;
            }
            if (newDn != null || oldDn != null) {
                dirContext.rename(newDn, oldDn);
            } else {
                throw new UserStoreException("Couldn't resolve new or old DN. newDn : " + newDn + ", oldDn : " + oldDn);
            }
        } catch (NamingException | UserStoreException e) {
            String errorMessage = "Error while moving the user organization. User ID : " + userID;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }
        finally {
            JNDIUtil.closeNamingEnumeration(returnedResultList);
        }
    }

    /**
     * This method creates a subDirectory in the LDAP.
     *
     * @param dn
     * @throws UserStoreException
     */
    public void createOu(String dn) throws UserStoreException {

        DirContext dirContext = null;
        try {
            dirContext = connectionSource.getContext();
            Attributes attributes = new BasicAttributes(true);
            Attribute objClass = new BasicAttribute("objectclass");
            objClass.add("top");
            objClass.add("organizationalUnit");
            attributes.put(objClass);
            dirContext.createSubcontext(dn, attributes);
            if (log.isDebugEnabled()) {
                log.debug("Successfully created the DN : " + dn);
            }
        } catch (UserStoreException e) {
            log.error("Error obtaining directory context to create DN : " + dn, e);
            throw e;
        } catch (NamingException e) {
            String errorMsg = "Error while creating the DN : " + dn;
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, e);
        } finally {
            if (dirContext != null) {
                JNDIUtil.closeContext(dirContext);
            }
        }
    }

    private DirContext getOrganizationDirectoryContext(String dn) throws UserStoreException {

        DirContext mainDirContext = this.connectionSource.getContext();
        try {
            return (DirContext) mainDirContext.lookup(escapeDNForSearch(dn));
        } catch (NamingException e) {
            String errorMessage = "Can not access the directory context for the DN : " + dn;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeContext(mainDirContext);
        }
    }

    protected void persistUser(String userID, String userName, Object credential, String[] roleList,
            Map<String, String> claims) throws UserStoreException {

        OrganizationManager organizationService = CustomUserStoreDataHolder.getInstance().getOrganizationService();
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
            orgIdentifier = ROOT_ORG_NAME;
        }
        Organization organization;
        try {
            orgIdentifier = nameAsIdentifier ?
                    organizationService.getOrganizationIdByName(orgIdentifier) : orgIdentifier;
            organization = organizationService.getOrganization(orgIdentifier, false);
            claims.put(orgNameClaimUri, organization.getName());
            claims.put(orgIdClaimUri, organization.getId());
        } catch (OrganizationManagementClientException e) {
            String errorMsg = "Failed resolving organization name : " + orgIdentifier + " to an organization id";
            if (log.isDebugEnabled()) {
                log.debug(errorMsg, e);
            }
            throw new UserStoreException(errorMsg, e);
        } catch (OrganizationManagementException e) {
            String errorMsg = "Error while obtaining organization Id : " + e.getMessage();
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, e);
        }
        // Authorize user creation request
        if (!isAuthorized(claims.get(orgIdClaimUri), ORGANIZATION_USER_CREATE_PERMISSION)) {
            throw new UserStoreException("Not authorized");
        }
        // Check if organization is active
        if (!Organization.OrgStatus.ACTIVE.equals(organization.getStatus())) {
            String errorMsg = "Organization is not active : " + orgIdentifier;
            if (log.isDebugEnabled()) {
                log.debug(errorMsg);
            }
            throw new UserStoreException(errorMsg);
        }
        String orgDn;
        try {
            // Get user store configs by organization ID
            orgDn = organizationService.getUserStoreConfigs(orgIdentifier).get(DN).getValue();
        } catch (OrganizationManagementException e) {
            String errorMsg = "Error while obtaining organization metadata : " + e.getMessage();
            log.error(errorMsg, e);
            throw new UserStoreException(errorMsg, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Organization id : " + orgIdentifier + ", DN : " + orgDn);
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
            String errorMessage =
                    "Cannot access the directory context or " + "user already exists in the system for user :"
                            + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            JNDIUtil.closeContext(dirContext);
            // Clearing password byte array
            UserCoreUtil.clearSensitiveBytes(passwordToStore);
        }

        if (roleList != null && roleList.length > 0) {
            try {
                /* update the user roles */
                doUpdateRoleListOfUserWithID(userID, null, roleList);
                if (log.isDebugEnabled()) {
                    log.debug("Roles are added for user  : " + userName + " successfully.");
                }
            } catch (UserStoreException e) {
                String errorMessage = "User is added. But error while updating role list of user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e);
                }
                throw new UserStoreException(errorMessage, e);
            }
        }
    }

    private String escapeSpecialCharactersForDN(String text) {

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
                log.debug("value after escaping special characters in " + text + " : " + sb.toString());
            }
            return sb.toString();
        } else {
            return text;
        }
    }

    private List<ExpressionCondition> getExpressionConditions(Condition condition) {

        List<ExpressionCondition> expressionConditions = new ArrayList<>();
        getExpressionConditionsAsList(condition, expressionConditions);
        return expressionConditions;
    }

    private int getLimit(int limit, boolean isMemberShipPropertyFound) {

        int givenMax;

        try {
            givenMax = Integer
                    .parseInt(realmConfig.getUserStoreProperty(UserCoreConstants.RealmConfig.PROPERTY_MAX_USER_LIST));
        } catch (Exception e) {
            givenMax = UserCoreConstants.MAX_USER_ROLE_LIST;
        }
        /*
        For group filtering can't apply pagination. We don't know how many group details will be return.
        So set to max value.
         */
        if (isMemberShipPropertyFound || limit > givenMax) {
            limit = givenMax;
        }
        return limit;
    }

    private int getOffset(int offset) {

        if (offset <= 0) {
            offset = 0;
        } else {
            offset = offset - 1;
        }
        return offset;
    }

    private void getExpressionConditionsAsList(Condition condition, List<ExpressionCondition> expressionConditions) {

        if (condition instanceof ExpressionCondition) {
            ExpressionCondition expressionCondition = (ExpressionCondition) condition;
            expressionCondition.setAttributeValue(
                    escapeSpecialCharactersForFilterWithStarAsRegex(expressionCondition.getAttributeValue()));
            expressionConditions.add(expressionCondition);
        } else if (condition instanceof OperationalCondition) {
            Condition leftCondition = ((OperationalCondition) condition).getLeftCondition();
            getExpressionConditionsAsList(leftCondition, expressionConditions);
            Condition rightCondition = ((OperationalCondition) condition).getRightCondition();
            getExpressionConditionsAsList(rightCondition, expressionConditions);
        }
    }

    private List<String> performLDAPSearch(LdapContext ldapContext, LDAPSearchSpecification ldapSearchSpecification,
            String orgSearchBase, int pageSize, int offset, List<ExpressionCondition> expressionConditions)
            throws UserStoreException {

        byte[] cookie;
        int pageIndex = -1;
        boolean isGroupFiltering = ldapSearchSpecification.isGroupFiltering();
        boolean isUsernameFiltering = ldapSearchSpecification.isUsernameFiltering();
        boolean isClaimFiltering = ldapSearchSpecification.isClaimFiltering();
        boolean isMemberShipPropertyFound = ldapSearchSpecification.isMemberShipPropertyFound();

        String[] searchBaseArray = { orgSearchBase };
        if (log.isDebugEnabled()) {
            log.debug("Searching in the subdirectory : " + Arrays.toString(searchBaseArray));
        }
        String searchFilter = ldapSearchSpecification.getSearchFilterQuery();
        SearchControls searchControls = ldapSearchSpecification.getSearchControls();
        // Do not search in the sub trees
//        searchControls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        List<String> returnedAttributes = Arrays.asList(searchControls.getReturningAttributes());
        NamingEnumeration<SearchResult> answer = null;
        List<String> users = new ArrayList<>();

        if (log.isDebugEnabled()) {
            log.debug(String.format("Searching for user(s) with SearchFilter: %s and page size %d", searchFilter,
                    pageSize));
        }
        try {
            for (String searchBase : searchBaseArray) {
                do {
                    List<String> tempUserList = new ArrayList<>();
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
                    log.debug(String.format("Error occurred while searching for user(s) for filter: %s", searchFilter));
                }
            } else {
                log.error(String.format("Error occurred while searching for user(s) for filter: %s", searchFilter));
                throw new UserStoreException(e.getMessage(), e);
            }
        } catch (NamingException e) {
            log.error(String.format("Error occurred while searching for user(s) for filter: %s, %s", searchFilter,
                    e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } catch (IOException e) {
            log.error(String.format("Error occurred while doing paginated search, %s", e.getMessage()));
            throw new UserStoreException(e.getMessage(), e);
        } finally {
            JNDIUtil.closeNamingEnumeration(answer);
        }
        return users;
    }

    private List<String> getUserListFromSearch(boolean isGroupFiltering, List<String> returnedAttributes,
            NamingEnumeration<SearchResult> answer, boolean isSingleAttributeFilter) throws UserStoreException {

        List<String> tempUserList;
        if (isGroupFiltering) {
            tempUserList = getUserListFromGroupFilterResult(answer, returnedAttributes, isSingleAttributeFilter);
        } else {
            tempUserList = getUserListFromNonGroupFilterResult(answer, returnedAttributes);
        }
        return tempUserList;
    }

    private boolean isSingleAttributeFilterOperation(List<ExpressionCondition> expressionConditions) {

        /*
        The size of the expression condition is used to verify the type of filter operation since the up
        coming steps needs to verify whether this is a multi attribute scenario or single attribute scenario.
        (value will equal to 1 for a single attribute filter)
        */
        return (expressionConditions.size() == 1);
    }

    private List<String> membershipGroupFilterPostProcessing(boolean isUsernameFiltering, boolean isClaimFiltering,
            List<ExpressionCondition> expressionConditions, List<String> tempUserList) throws UserStoreException {

        List<String> users;
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

    private void generatePaginatedUserList(int pageIndex, int offset, int pageSize, List<String> tempUserList,
            List<String> users) {

        int needMore;
        // Handle pagination depends on given offset, i.e. start index.
        if (pageIndex == (offset / pageSize)) {
            int startPosition = (offset % pageSize);
            if (startPosition < tempUserList.size() - 1) {
                users.addAll(tempUserList.subList(startPosition, tempUserList.size()));
            } else if (startPosition == tempUserList.size() - 1) {
                users.add(tempUserList.get(tempUserList.size() - 1));
            }
        } else if (pageIndex == (offset / pageSize) + 1) {
            needMore = pageSize - users.size();
            if (tempUserList.size() >= needMore) {
                users.addAll(tempUserList.subList(0, needMore));
            } else {
                users.addAll(tempUserList);
            }
        }
    }

    private static byte[] parseControls(Control[] controls) {

        byte[] cookie = null;
        // Handle the paged results control response
        if (controls != null) {
            for (int i = 0; i < controls.length; i++) {
                if (controls[i] instanceof PagedResultsResponseControl) {
                    PagedResultsResponseControl prrc = (PagedResultsResponseControl) controls[i];
                    cookie = prrc.getCookie();
                }
            }
        }
        return cookie;
    }

    private List<String> getUserListFromGroupFilterResult(NamingEnumeration<SearchResult> answer,
            List<String> returnedAttributes, boolean isSingleAttributeFilter) throws UserStoreException {

        // Can be user DN list or username list
        List<String> userListFromSearch = new ArrayList<>();
        // Multi group retrieval
        int count = 0;
        NamingEnumeration<?> attrs = null;
        List<String> finalUserList;

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
                    /*
                     * If returnedAttributes doesn't contain 'member' attribute, then it's memberOf group filter.
                     * If so we  don't need to do post processing.
                     */
                    if (!returnedAttributes
                            .contains(realmConfig.getUserStoreProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE))
                            || count == 1) {
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

        // If 'member' attribute found, we need iterate over users' DN list and get userName.
        if (returnedAttributes.contains(realmConfig.getUserStoreProperty(LDAPConstants.MEMBERSHIP_ATTRIBUTE))) {
            finalUserList = getUserNamesFromDNList(userListFromSearch);
        } else {
            finalUserList = userListFromSearch;
        }
        return finalUserList;
    }

    private List<String> getUserListFromNonGroupFilterResult(NamingEnumeration<SearchResult> answer,
            List<String> returnedAttributes) throws UserStoreException {

        List<String> finalUserList = new ArrayList<>();
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
                String propertyValue = attrBuffer.toString();
                Attribute serviceNameObject = attributes.get(returnedAttributes.get(1));
                String serviceNameAttributeValue = null;
                if (serviceNameObject != null) {
                    serviceNameAttributeValue = (String) serviceNameObject.get();
                }
                /* Length needs to be more than userAttributeSeparator.length() for a valid attribute,
                since we attach userAttributeSeparator. */
                if (propertyValue.trim().length() > userAttributeSeparator.length()) {
                    if (LDAPConstants.SERVER_PRINCIPAL_ATTRIBUTE_VALUE.equals(serviceNameAttributeValue)) {
                        continue;
                    }
                    propertyValue = propertyValue
                            .substring(0, propertyValue.length() - userAttributeSeparator.length());
                    finalUserList.add(propertyValue);
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

    private List<String> getMatchUsersFromMemberList(List<ExpressionCondition> expressionConditions,
            List<String> userNames) {
        /*
        If group filtering and username filtering found, we need to get match users names only.
        'member' filtering retrieve all the members once the conditions matched because 'member' is a
        multi valued attribute.
        */
        List<String> derivedUserList = new ArrayList<>();

        for (ExpressionCondition expressionCondition : expressionConditions) {
            if (ExpressionAttribute.USERNAME.toString().equals(expressionCondition.getAttributeName())) {
                derivedUserList.addAll(getMatchUserNames(expressionCondition, userNames));
            }
        }
        LinkedHashSet<String> linkedHashSet = new LinkedHashSet<>();
        linkedHashSet.addAll(derivedUserList);
        derivedUserList.clear();
        derivedUserList.addAll(linkedHashSet);
        return derivedUserList;
    }

    private List<String> getUserNamesFromDNList(List<String> userListFromSearch) throws UserStoreException {

        List<String> userNameList = new ArrayList<>();
        DirContext dirContext = this.connectionSource.getContext();
        String userNameProperty = realmConfig.getUserStoreProperty(LDAPConstants.USER_NAME_ATTRIBUTE);
        String displayNameAttribute = realmConfig.getUserStoreProperty(LDAPConstants.DISPLAY_NAME_ATTRIBUTE);
        String[] requiredAttributes = { userNameProperty, displayNameAttribute };

        for (String user : userListFromSearch) {
            try {
                String displayName = null;
                String userName = null;
                Attributes userAttributes = dirContext.getAttributes(escapeDNForSearch(user), requiredAttributes);

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
                }
                String domainName = realmConfig.getUserStoreProperty(PROPERTY_DOMAIN_NAME);
                /* Username will be null in the special case where the username attribute has changed to another
                and having different userNameProperty than the current user-mgt.xml. */
                if (userName != null) {
                    user = UserCoreUtil.getCombinedName(domainName, userName, displayName);
                    userNameList.add(user);
                } else {
                    // Skip listing users which are not applicable to current user-mgt.xml
                    if (log.isDebugEnabled()) {
                        log.debug(String.format("User %s doesn't have the user name property %s", user,
                                userNameProperty));
                    }
                }
            } catch (NamingException e) {
                log.error(String.format("Error in reading user information in the user store for the user %s, %s", user,
                        e.getMessage()));
                throw new UserStoreException(e.getMessage(), e);
            }
        }
        return userNameList;
    }

    private List<String> getUserListFromClaimFiltering(List<ExpressionCondition> expressionConditions,
            List<String> tempUserList) throws UserStoreException {

        List<String> claimSearchUserList = new ArrayList<>();
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
            tempAnswer = claimSearchDirContext
                    .search(claimSearch.getSearchBases(), claimSearch.getSearchFilterQuery(), claimSearchControls);
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

    private List<String> getMatchUserNames(ExpressionCondition expressionCondition, List<String> users) {

        List<String> newUserNameList = new ArrayList<>();

        for (String user : users) {
            if (ExpressionOperation.SW.toString().equals(expressionCondition.getOperation()) && user
                    .startsWith(expressionCondition.getAttributeValue()) && !newUserNameList.contains(user)) {
                newUserNameList.add(user);
            } else if (ExpressionOperation.EQ.toString().equals(expressionCondition.getOperation()) && user
                    .equals(expressionCondition.getAttributeValue()) && !newUserNameList.contains(user)) {
                newUserNameList.add(user);
            } else if (ExpressionOperation.CO.toString().equals(expressionCondition.getOperation()) && user
                    .contains(expressionCondition.getAttributeValue()) && !newUserNameList.contains(user)) {
                newUserNameList.add(user);
            } else if (ExpressionOperation.EW.toString().equals(expressionCondition.getOperation()) && user
                    .endsWith(expressionCondition.getAttributeValue()) && !newUserNameList.contains(user)) {
                newUserNameList.add(user);
            }
        }
        return newUserNameList;
    }

    private String escapeSpecialCharactersForFilterWithStarAsRegex(String dnPartial) {

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
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                case '\\':
                    if (dnPartial.charAt(i + 1) == '*') {
                        sb.append("\\2a");
                        i++;
                        break;
                    }
                    sb.append("\\5c");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }

    private boolean isIgnorePartialResultException() {

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

    private String getAuthenticatedUserId() throws org.wso2.carbon.user.api.UserStoreException {

        return getUserIDFromUserName(getAuthenticatedUsername(), getTenantId());
    }

    private String getAuthenticatedUsername() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    private String getUserIDFromUserName(String username, int tenantId) throws
            org.wso2.carbon.user.api.UserStoreException {

        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) CustomUserStoreDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            return userStoreManager.getUserIDFromUserName(username);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg = "Error obtaining ID for the username : " + username + ", tenant id : " + tenantId;
            throw new org.wso2.carbon.user.api.UserStoreException(errorMsg, e);
        }
    }

//    private int getTenantId() {
//
//        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
//    }

    private boolean isAuthorized(String organizationId, String permission)
            throws org.wso2.carbon.user.core.UserStoreException {

        // To create a user inside an organization
        // you should have '/permission/admin/organizations/create' over the subject organization
        OrganizationAuthorizationDao authorizationDao =
                CustomUserStoreDataHolder.getInstance().getOrganizationAuthDao();
        try {
            return authorizationDao.isUserAuthorized(getAuthenticatedUserId(), organizationId, permission);
        } catch (OrganizationManagementException | org.wso2.carbon.user.api.UserStoreException e) {
            String errorMsg =
                    "Error while authorizing the action : " + permission + ", organization id : " + organizationId;
            log.error(errorMsg, e);
            throw new org.wso2.carbon.user.core.UserStoreException(errorMsg, e);
        }
    }

    /**
     * Escaping ldap search filter special characters in a string
     *
     * @param dnPartial String to replace special characters
     * @return
     */
    private String escapeSpecialCharactersForFilter(String dnPartial) {

        boolean replaceEscapeCharacters = true;
        dnPartial.replace("\\*", "*");
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
            for (int i = 0; i < dnPartial.length(); i++) {
                char currentChar = dnPartial.charAt(i);
                switch (currentChar) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(currentChar);
                }
            }
            return sb.toString();
        } else {
            return dnPartial;
        }
    }
}
