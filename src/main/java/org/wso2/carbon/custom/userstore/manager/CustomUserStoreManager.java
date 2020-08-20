package org.wso2.carbon.custom.userstore.manager;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.custom.userstore.manager.internal.CustomUserStoreDataHolder;
import org.wso2.carbon.identity.organization.mgt.core.OrganizationManager;
import org.wso2.carbon.identity.organization.mgt.core.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.mgt.core.model.UserStoreConfig;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_NAME_SCIM2_ATTRIBUTE;
import static org.wso2.carbon.custom.userstore.manager.Constants.ORGANIZATION_NAME_SCIM2_DEFAULT_ATTRIBUTE;
import static org.wso2.carbon.custom.userstore.manager.Constants.ROOT_ORG_NAME;
import static org.wso2.carbon.identity.organization.mgt.core.constant.OrganizationMgtConstants.DN;

import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.common.User;
import org.wso2.carbon.user.core.ldap.LDAPConstants;
import org.wso2.carbon.user.core.ldap.UniqueIDReadWriteLDAPUserStoreManager;
import org.wso2.carbon.user.core.util.JNDIUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import javax.naming.Name;
import javax.naming.NameParser;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.DirContext;
import java.util.Map;

public class CustomUserStoreManager extends UniqueIDReadWriteLDAPUserStoreManager {

    private static final Log log = LogFactory.getLog(CustomUserStoreManager.class);

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
            dirContext.createSubcontext("ou=test1,ou=Users,dc=wso2,dc=org", attributes);
            if (log.isDebugEnabled()) {
                log.debug("Successfully created the DN : " + dn);
            }
        } catch (UserStoreException e) {
            log.error("Error obtaining directory context to create DN : " + dn, e);
            throw e;
        } catch (NamingException e) {
            log.error("Error while creating DN : " + dn, e);
            throw new UserStoreException(e);
        } finally {
            if (dirContext != null) {
                JNDIUtil.closeContext(dirContext);
            }
        }
    }

    @Override
    public User doAddUserWithID(String userName, Object credential, String[] roleList, Map<String, String> claims,
                                String profileName, boolean requirePasswordChange) throws UserStoreException {

        String userID = getUniqueUserID();
        persistUser(userID, userName, credential, roleList, claims);
        return getUser(userID, userName);
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

        String orgClaimUri = !StringUtils.isBlank(IdentityUtil.getProperty(ORGANIZATION_NAME_SCIM2_ATTRIBUTE))
                ? IdentityUtil.getProperty(ORGANIZATION_NAME_SCIM2_ATTRIBUTE).trim() : ORGANIZATION_NAME_SCIM2_DEFAULT_ATTRIBUTE;
        // If org name is not defined, user will be created under ROOT
        String orgName = (claims != null && !StringUtils.isBlank(claims.get(orgClaimUri)))
                ? claims.get(orgClaimUri).trim() : ROOT_ORG_NAME;
        DirContext dirContext;
        if (orgName.equalsIgnoreCase(ROOT_ORG_NAME)) {
            if (log.isDebugEnabled()) {
                log.debug("Organization name : " + ROOT_ORG_NAME);
            }
            dirContext = super.getSearchBaseDirectoryContext();
        } else {
            OrganizationManager organizationService = CustomUserStoreDataHolder.getInstance().getOrganizationService();
            Map<String, UserStoreConfig> userStoreConfigs;
            try {
                String orgId = organizationService.getOrganizationIdByName(orgName);
                userStoreConfigs = organizationService.getUserStoreConfigs(orgId);
            } catch (OrganizationManagementException e) {
                String errorMsg = "Error while retrieving organization information" + orgName;
                log.error(errorMsg);
                throw new UserStoreException(errorMsg, e);
            }
            String orgDn = userStoreConfigs.get(DN).getValue();
            if (log.isDebugEnabled()) {
                log.debug("Organization name : " + orgName + ", DN : " + orgDn);
            }
            dirContext = getOrganizationDirectoryContext(orgDn);
        }

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

    /**
     * Escaping ldap DN special characters in a String value
     *
     * @param text String to replace special characters
     * @return
     */
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
}
